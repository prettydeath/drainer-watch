"""GitHub / paper research rules G1-G13: synthetic receipts / blocks for every rule, negatives for the false-positive
guards, tier policy (never T1 from one heuristic)."""
import json

import pytest

from drainerwatch import bytecode, detectors, grules, rollup, scan, seeds, wscan
from drainerwatch.constants import (LEGIT_7702_DELEGATES, NFT_TRANSFER_HELPERS, TOPIC_TRANSFER, TRUSTED_ROUTERS)
from drainerwatch.db import add_evidence
from drainerwatch.seeds import SeedSet
from drainerwatch.util import selector
from tests.helpers import a, approval_log, make_ctx, pad, transfer_log, tx_hash
from tests.test_kits import block
from tests.test_kits_k import KitRpc, dispatcher, tx
from tests.test_wrules import CODE, USDT, V, CodeAtRpc, ev, lg, order_fulfilled, rc, run, w

ROUTER = next(iter(TRUSTED_ROUTERS))
HELPER = next(iter(NFT_TRANSFER_HELPERS))
NFT = a(0x4F4F)
ETH = 10 ** 18


@pytest.fixture(autouse=True)
def no_etherscan(monkeypatch):
    monkeypatch.setattr(wscan, "etherscan", lambda ctx: None)


def run_bp(blocks_txs, logs=(), codes=None, meta_extra=None, rpc_cls=KitRpc, ctx=None, **kw):
    """process_chunk + eth_block_pass with txmeta (receipts source) that can carry nlogs / created per tx."""
    lo, hi = min(blocks_txs), max(blocks_txs)
    bl = [block(n, blocks_txs.get(n, [])) for n in range(lo, hi + 1)]
    rpc = rpc_cls(bl, codes=codes or {}, symbols={USDT: ("USDT", 6)}, **kw)
    ctx = ctx or make_ctx(rpc)
    m = {}
    for n, ts in blocks_txs.items():
        for t in ts:
            m[t["hash"]] = dict({"from": t["from"], "to": t["to"], "block": n, "created": None, "status": 1, "nlogs": 1},
                                **(meta_extra or {}).get(t["hash"], {}))
    scan.process_chunk(ctx, lo, hi, list(logs), txmeta=m)
    scan.eth_block_pass(ctx, lo, hi, txmeta=m)
    return ctx, {r["address"]: r for r in rollup.rollup(ctx.conn, SeedSet(), {})}


def nft_log(h, token, frm, to, ident, li=0, block_n=100):
    return lg(h, token, [TOPIC_TRANSFER, pad(frm), pad(to), "0x" + f"{ident:064x}"], block=block_n, li=li)


# ---------- tier policy ----------
def test_tier_policy_never_t1_from_one_g_heuristic():
    t = detectors.assign_tier
    for one in detectors.G_T2:
        assert t({one}, 5, True) == "T2", one
    for one in detectors.G_T3:
        assert t({one}, 5, True) == "T3", one
    assert t({"fake_call_multi", "router_sweep_multi"}, 3, True) == "T1"          # two different G rules
    assert t({"zero_nonce_multi", "zero_nonce_pull"}, 3, True) == "T2"            # one rule (G13) twice
    assert t({"fake_call_multi", "deploy_drain"}, 3, True) == "T1"                # G T2 + W T2
    assert t({"phish_deploy", "phish_multicall"}, 2, True) == "T1"
    assert t({"phish_deploy", "phish_multicall"}, 1, True) == "T2"
    for static in ("codehash_cluster", "full_balance_pull", "c2_config_intel", "cex_sweep_capped"):
        assert t({static}, 3, True) is None


# ---------- G1 fake-function call ----------
def _fake(victims, value=12_345_678_900_000_000, sel="5fba79f5", to=a(0xFA4E), extra=()):
    txs = {100 + i: [tx(tx_hash(10 + i), V(i), to, "0x" + sel, value)] for i in range(victims)}
    for n, t in extra:
        txs.setdefault(n, []).append(t)
    return run_bp(txs)


def test_g1_fake_call_to_eoa():
    eoa = a(0xFA4E)
    ctx, rows = _fake(1)
    assert rows[eoa]["tier"] == "T3" and rows[eoa]["labels"] == ["fake_call"]
    (d,) = ev(ctx, "fake_call")
    assert d["name"] == "SecurityUpdate()" and d["victim"] == V(0)
    _, rows = _fake(3)
    assert rows[eoa]["tier"] == "T2" and "fake_call_multi" in rows[eoa]["labels"] and rows[eoa]["victims"] == 3
    assert grules.fake_call_name("0x372500ab", 1) == "claimRewards()" and grules.fake_call_name("0x372500ab00", 1) is None


def test_g1_false_positive_filters():
    eoa = a(0xFA4E)
    _, rows = _fake(1, value=5 * 10 ** 16)                    # round value from a single sender: a payment
    assert eoa not in rows
    _, rows = _fake(1, extra=[(101, tx(tx_hash(90), V(0), a(0x77), "0x", 1))])   # sender active in the next block
    assert eoa not in rows
    _, rows = _fake(1, sel="a9059cbb")                         # not a bait name
    assert eoa not in rows
    ctx, rows = run_bp({100: [tx(tx_hash(10), V(0), eoa, "0x5fba79f5", 12_345_678_900_000_000)]},
                       nonces={eoa: 5000})                    # busy receiver
    assert eoa not in rows


def test_g1_contract_variant_zero_logs_value_forwarded():
    c = a(0xC0C0)
    txs = {100: [tx(tx_hash(20 + i), V(i), c, "0xdeadbeef", ETH) for i in range(3)]}
    meta = {tx_hash(20 + i): {"nlogs": 0} for i in range(3)}
    ctx, rows = run_bp(txs, codes={c: dispatcher(["deadbeef"])}, meta_extra=meta, balances={(c, 99): 0, (c, 100): 0})
    assert rows[c]["tier"] == "T2" and {"fake_call_contract", "fake_call_contract_multi"} <= set(rows[c]["labels"])
    meta = {tx_hash(20 + i): {"nlogs": 2} for i in range(3)}  # the call emitted events: an ordinary dapp call
    _, rows = run_bp(txs, codes={c: dispatcher(["deadbeef"])}, meta_extra=meta, balances={(c, 99): 0, (c, 100): 0})
    assert c not in rows


# ---------- G2 many funders ----------
def test_g2_many_funders_into_fresh_eoa():
    r = a(0xF00D)
    vals = [5 * 10 ** 16 + i * 10 ** 14 for i in range(7)]
    txs = {100: [tx(tx_hash(30 + i), V(i), r, "0x", v, nonce=10 + i) for i, v in enumerate(vals)]}
    ctx, rows = run_bp(txs, nonces={r: 1})
    assert rows[r]["tier"] == "T3" and rows[r]["labels"] == ["many_funders"] and rows[r]["victims"] == 7
    txs = {100: [tx(tx_hash(30 + i), V(i), r, "0x", v, nonce=0) for i, v in enumerate(vals)]}   # sybil batch
    _, rows = run_bp(txs, nonces={r: 1})
    assert r not in rows
    txs = {100: [tx(tx_hash(30 + i), V(i), r, "0x", v, nonce=10 + i) for i, v in enumerate(vals[:6])]}
    _, rows = run_bp(txs, nonces={r: 1})
    assert r not in rows
    assert grules.funders_hit([(V(i), 10 ** 17 * (1 + i), i, "h", 1) for i in range(7)]) is None   # amounts too spread


# ---------- G3 deploy-time phishing contract ----------
def test_g3_phish_deploy_and_multicall_drain():
    c, aa, bb, dep, col = a(0xC3C3), a(0xA1), a(0xB1), a(0xDE9), a(0xC011)
    code = dispatcher(["caa5c23f", "8da5cb5b"])
    assert grules.phish_traits(code) == ["multicall((address,bytes)[])"]
    assert grules.phish_traits(dispatcher(["caa5c23f", "70a08231"])) is None          # has balanceOf: a token
    create = dict(tx(tx_hash(40), dep, None, "0x6080"), to=None)
    inner = "0x" + "caa5c23f" + w(32) + w(1) + "23b872dd" + "00" * 28
    calls = [tx(tx_hash(41 + i), col, c, inner) for i in range(2)]
    logs = [transfer_log(tx_hash(41 + i), USDT, V(i), col, 50_000_000, li=i) for i in range(2)]
    ctx, rows = run_bp({100: [create] + calls}, logs=logs, codes={c: code, bb: dispatcher(["3ccfd60b"])},
                       meta_extra={tx_hash(40): {"created": c}}, storage={(c, 0): int(aa, 16), (aa, 0): int(bb, 16)})
    assert {"phish_deploy", "phish_multicall"} <= set(rows[c]["labels"]) and rows[c]["tier"] == "T1"
    ctx, rows = run_bp({100: [create]}, codes={c: code, bb: dispatcher(["a9059cbb"])},
                       meta_extra={tx_hash(40): {"created": c}}, storage={(c, 0): int(aa, 16), (aa, 0): int(bb, 16)})
    assert c not in rows                                     # no withdraw() at the end of the storage chain


# ---------- G4 router pull + sweep ----------
def test_g4_router_pull_and_sweep_to_third_party():
    x = a(0x5EE9)

    def sweep(i, to=x, tokens=(USDT, USDT)):
        h = tx_hash(50 + i)
        return rc(h, V(i), ROUTER, [transfer_log(h, tokens[0], V(i), ROUTER, 90_000_000, li=0),
                                    transfer_log(h, tokens[1], ROUTER, to, 90_000_000, li=1)])
    ctx, rows = run([sweep(1)])
    assert rows[x]["tier"] == "T3" and rows[x]["labels"] == ["router_sweep"]
    _, rows = run([sweep(1), sweep(2)])
    assert rows[x]["tier"] == "T2" and "router_sweep_multi" in rows[x]["labels"]
    _, rows = run([sweep(1, to=V(1))])                       # sweep back to tx.from: normal
    assert not rows
    _, rows = run([sweep(1, tokens=(USDT, a(0x7777)))])     # a swap: two tokens move
    assert x not in rows


# ---------- G5 NFT ----------
def test_g5_bulk_transfer_helper_to_one_recipient():
    x = a(0xB0B0)
    rcs = []
    for i in range(3):
        h = tx_hash(60 + i)
        rcs.append(rc(h, V(i), HELPER, [nft_log(h, NFT, V(i), x, 10 * i + k, li=k) for k in range(2)]))
    _, rows = run(rcs[:1])
    assert rows[x]["tier"] == "T3" and rows[x]["labels"] == ["nft_bulk"]
    _, rows = run(rcs)
    assert rows[x]["tier"] == "T2" and "nft_bulk_multi" in rows[x]["labels"]
    h = tx_hash(70)                                           # a single NFT moved: not a bulk sweep
    _, rows = run([rc(h, V(1), HELPER, [nft_log(h, NFT, V(1), x, 1)])])
    assert not rows


def test_g5_seaport_fees_take_the_price():
    ful = a(0xF111)
    logs = [order_fulfilled(tx_hash(80 + i), V(i), ful, [(2, NFT, 7 + i, 1)],
                            [(0, a(0), 0, 10 ** 9, V(i)), (0, a(0), 0, 10 ** 12, ful)]) for i in (1, 2)]
    rcs = [rc(x["transactionHash"], ful, a(0x5EA), [x]) for x in logs]
    ctx, rows = run(rcs[:1])
    assert rows[ful]["tier"] == "T3" and rows[ful]["labels"] == ["seaport_fee_drain"]
    _, rows = run(rcs)
    assert rows[ful]["tier"] == "T2" and "seaport_fee_multi" in rows[ful]["labels"]
    gift = order_fulfilled(tx_hash(90), V(3), ful, [(2, NFT, 9, 1)], [(0, a(0), 0, 10 ** 17, V(3))])   # real price
    from drainerwatch import wrules
    assert grules.seaport_fee_drain(wrules.decode_order_fulfilled(gift)) is None


# ---------- G6 poisoning ----------
def test_g6_tiny_stablecoin_from_lookalike_is_t3_only():
    real = "0x1a2b3c" + "0" * 30 + "dead"
    fake = "0x1a2" + "f" * 33 + "dead"
    h1, h2 = tx_hash(100), tx_hash(101)
    rcs = [rc(h1, V(1), USDT, [transfer_log(h1, USDT, V(1), real, 500_000_000)]),
           rc(h2, fake, USDT, [transfer_log(h2, USDT, fake, V(1), 100_000)])]
    ctx, rows = run(rcs)
    assert rows[fake]["tier"] == "T3" and rows[fake]["labels"] == ["poison_tiny"] and rows[fake]["drains"] == 0
    assert rows[fake]["cluster"].startswith("px_")
    typo = real[:-6] + "aadead"                               # 34 matching chars: a typo, not poisoning
    assert grules.lookalike_of(typo, [real]) is None and grules.lookalike_of(fake, [real]) == real
    assert grules.similarity(real, typo) >= 20


def test_g6_poison_clusters_share_lookalikes():
    roots = grules.poison_clusters([("s1", ["L1", "tx1"]), ("s2", ["L1"]), ("s3", ["L9"])])
    assert roots["s1"] == roots["s2"] != roots["s3"]


def test_g6_batch_shape():
    legs = [dict(token=USDT, value=0, frm=V(i), to=a(0x99)) for i in range(6)]
    assert grules.poison_batch(legs, 6, 6, {USDT}, set())["legs"] == 6
    assert grules.poison_batch(legs, 6, 9, {USDT}, set()) is None                 # other events in the tx
    legs2 = [dict(l, value=i) for i, l in enumerate(legs)]
    assert grules.poison_batch(legs2, 6, 6, {USDT}, set()) is None               # all amounts different


# ---------- G7 lookalike contract ----------
def test_g7_lookalike_contract_creation():
    c = USDT[:5] + "9" * 34 + USDT[-3:]
    h = tx_hash(110)
    ctx, rows = run([rc(h, a(0xDE), None, [], created=c)], codes={c: CODE})
    assert rows[c]["tier"] == "T3" and rows[c]["labels"] == ["lookalike_contract"]
    assert grules.lookalike_contract(a(0x1234), {USDT}) is None


# ---------- G8 counterfactual destination ----------
def test_g8_counterfactual_child_forwards_preexisting_balance():
    f, op = a(0xFAC7), a(0x0B)
    kids = [a(0x6101), a(0x6102)]
    rcs = [rc(tx_hash(120 + i), op, f, [transfer_log(tx_hash(120 + i), USDT, k, a(0xEE), 90_000_000)])
           for i, k in enumerate(kids)]
    rpc = CodeAtRpc(before={k: "0x" for k in kids}, codes={f: CODE, **{k: CODE for k in kids}},
                    symbols={USDT: ("USDT", 6)}, nonces={k: 1 for k in kids})
    ctx, rows = run(rcs, rpc=rpc)
    assert rows[f]["tier"] == "T2" and {"counterfactual_forward", "counterfactual_multi"} <= set(rows[f]["labels"])
    rpc = CodeAtRpc(before={k: CODE for k in kids}, codes={f: CODE, **{k: CODE for k in kids}},
                    symbols={USDT: ("USDT", 6)}, nonces={k: 1 for k in kids})
    _, rows = run(rcs, rpc=rpc)                               # the child existed before: an ordinary contract
    assert f not in rows
    h = tx_hash(130)                                          # tokens came in and left in the same tx: pass-through
    rpc = CodeAtRpc(before={kids[0]: "0x"}, codes={f: CODE, kids[0]: CODE}, symbols={USDT: ("USDT", 6)})
    _, rows = run([rc(h, op, f, [transfer_log(h, USDT, op, kids[0], 90_000_000, li=0),
                                 transfer_log(h, USDT, kids[0], a(0xEE), 90_000_000, li=1)])], rpc=rpc)
    assert f not in rows


# ---------- G11 EIP-7702 ----------
def test_g11_forwarder_fingerprint():
    fwd = dispatcher([selector("initialize(address)"), selector("destination()")])
    assert bytecode.is_forwarder_7702(fwd)
    assert not bytecode.is_forwarder_7702(dispatcher([selector("initialize(address)"), "a9059cbb"]))
    d = a(0xF0F0)
    auths = [{"chainId": "0x1", "address": d, "nonce": "0x0", "yParity": "0x0", "r": "0x1", "s": "0x1"}]
    t = dict(tx(tx_hash(140), a(0x0B), a(0x0B)), type="0x4", authorizationList=auths)
    ctx, rows = run_bp({100: [t]}, codes={d: fwd})
    assert rows[d]["tier"] == "T3" and "forwarder_7702" in rows[d]["labels"]


def test_g11_legit_delegator_decoy_batch():
    mm = next(iter(LEGIT_7702_DELEGATES))
    x, h = a(0x7E7E), tx_hash(150)
    logs = [transfer_log(h, USDT, V(1), ROUTER, 1_000_000, li=0), transfer_log(h, USDT, V(1), x, 900_000_000, li=1)]
    codes = {V(1): "0xef0100" + mm[2:]}
    ctx, rows = run([rc(h, V(1), V(1), logs)], codes=codes, nonces={x: 0})
    assert rows[x]["tier"] == "T3" and "batch7702_decoy" in rows[x]["labels"]
    _, rows = run([rc(h, V(1), V(1), logs)], codes=codes, nonces={x: 12})    # a known recipient
    assert x not in rows
    _, rows = run([rc(h, V(1), V(1), logs[1:])], codes=codes, nonces={x: 0})  # no router leg: W8b territory
    assert x not in rows


# ---------- G12 / G13 ----------
def test_g12_increase_allowance_to_eoa_then_pull():
    s = a(0x5115)
    inp = "0x39509351" + w(s) + w(2 ** 255)
    ctx, rows = run_bp({100: [tx(tx_hash(160), V(1), USDT, inp)]})
    assert rows[s]["tier"] == "T3" and rows[s]["labels"] == ["increase_allowance_eoa"]
    add_evidence(ctx.conn, "eth", s, "eoa_spender_pull", tx_hash(161), 101, 1_800_000_101,
                 dict(victim=V(1), recipient=a(0xEE), token=USDT))
    r = {x["address"]: x for x in rollup.rollup(ctx.conn, SeedSet(), {})}[s]
    assert r["tier"] == "T2" and "increase_allowance_pull" in r["labels"]


def test_g13_zero_nonce_spender_at_approval():
    s = a(0x2E80)
    rcs = [rc(tx_hash(170 + i), V(i), USDT, [approval_log(tx_hash(170 + i), USDT, V(i), s, 2 ** 256 - 1)]) for i in range(3)]
    ctx, rows = run(rcs[:1], nonces={s: 0})
    assert rows[s]["tier"] == "T3" and rows[s]["labels"] == ["zero_nonce_spender"]
    _, rows = run(rcs, nonces={s: 0})
    assert rows[s]["tier"] == "T2" and "zero_nonce_multi" in rows[s]["labels"]
    _, rows = run(rcs, nonces={s: 7})
    assert s not in rows
    _, rows = run(rcs, codes={s: CODE}, nonces={s: 0})       # contract spender: dapps
    assert s not in rows


def test_g12_full_balance_marks_pull_evidence():
    class BalRpc(CodeAtRpc):
        def batch(self, calls, chunk=50, strict=True):
            return ["0x" + "0" * 64 for _ in calls]
    ctx = make_ctx(BalRpc())
    ctx.pev.append(dict(type="eoa_spender_pull", address=a(0x5), tx=tx_hash(1), block=100,
                        detail=dict(victim=V(1), token=USDT)))
    from drainerwatch import gscan
    gscan.full_balance(ctx, [])
    assert any(e["type"] == "full_balance_pull" for e in ctx.pev) and ctx.pev[0]["detail"]["full_balance"]


# ---------- FP guards / intel / TRON markers ----------
def test_fp_lists_loader(tmp_path):
    (tmp_path / "fp_list.csv").write_text("address,chain_id,comment\n0x" + "ab" * 20 + ",1,relayer\n0x" + "cd" * 20
                                         + ", 56,bridge\n", encoding="utf-8")
    (tmp_path / "failsafe_wallets.csv").write_text("0x" + "EF" * 20 + ",1,FailSafe Wallet Address\n", encoding="utf-8")
    eth = seeds.load_fp_lists("eth", tmp_path)
    assert eth == {"0x" + "ab" * 20: "fp_list: relayer", "0x" + "ef" * 20: "failsafe: FailSafe Wallet Address"}
    assert set(seeds.load_fp_lists("bsc", tmp_path)) == {"0x" + "cd" * 20}


def test_cex_deposit_sweep_is_capped():
    ctx = make_ctx()
    s, cex = a(0x5), a(0xCE)
    for i in range(3):
        add_evidence(ctx.conn, "eth", s, "split_pull", tx_hash(i), 100, 1_800_000_000, dict(victims=[V(i)], token=USDT))
        ctx.conn.execute("INSERT INTO drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,recipient)"
                         " VALUES('eth',?,0,1,?,?,?,'USDT',6,'10',10,?)", (tx_hash(i), V(i), s, USDT, cex))
    labels = {("eth", cex): ("Binance", "exchange", "Binance 14")}
    r = {x["address"]: x for x in rollup.rollup(ctx.conn, SeedSet(), labels)}[s]
    assert r["tier"] == "T1"
    ctx.conn.execute("CREATE TABLE IF NOT EXISTS victim_funding(chain TEXT, victim TEXT, cex_only INTEGER, "
                     "checked_at INTEGER, PRIMARY KEY(chain, victim))")
    ctx.conn.executemany("INSERT INTO victim_funding VALUES('eth',?,1,1)", [(V(i),) for i in range(3)])
    r = {x["address"]: x for x in rollup.rollup(ctx.conn, SeedSet(), labels)}[s]
    assert r["tier"] == "T3" and "cex_sweep_capped" in r["labels"]


def test_g9_intel_label_never_sets_a_tier(tmp_path, monkeypatch):
    f = tmp_path / "intel.csv"
    f.write_text("chain,address,label\neth," + a(0x5) + ",c2 config\n", encoding="utf-8")
    monkeypatch.setattr(rollup, "INTEL_CSV", f)
    ctx = make_ctx()
    add_evidence(ctx.conn, "eth", a(0x5), "fake_call", tx_hash(1), 100, 1_800_000_000, dict(victim=V(1)))
    r = {x["address"]: x for x in rollup.rollup(ctx.conn, SeedSet(), {})}[a(0x5)]
    assert r["tier"] == "T3" and "c2_config_intel" in r["labels"]


def test_g10_tron_sweeper_markers():
    code = dispatcher([selector("trc20Withdraw(address,address,address[],uint256[])"), "8da5cb5b"])
    assert bytecode.analyze(code, tvm=True)["tron_markers"] == ["trc20Withdraw"]
    assert bytecode.tron_sweep_abi(["owner", "sweepTokens"]) and not bytecode.tron_sweep_abi(["transfer"])
    ctx = make_ctx(chain="tron")
    tr = "T" + "A" * 33
    add_evidence(ctx.conn, "tron", tr, "bytecode", "0x1", 1, 1, dict(kit="tron_sweeper"))
    add_evidence(ctx.conn, "tron", tr, "split_xtx", "0x2", 1, 1, dict(victims=["T" + "B" * 33]))
    r = {x["address"]: x for x in rollup.rollup(ctx.conn, SeedSet(), {})}[tr]
    assert "tron_sweeper_kit" in r["labels"] and "kit_signature" not in r["labels"]


def test_codehash_cluster_is_score_only():
    ctx = make_ctx()
    for i in range(3):
        add_evidence(ctx.conn, "eth", a(0x10 + i), "fake_call", tx_hash(i), 100, 1_800_000_000, dict(victim=V(i)))
        ctx.conn.execute("INSERT INTO codes(chain,address,code_hash,size,skeleton,selectors) VALUES('eth',?,?,?,?,?)",
                         (a(0x10 + i), "0xabc", 500, "sk", json.dumps([])))
    rows = rollup.rollup(ctx.conn, SeedSet(), {})
    assert all("codehash_cluster" in r["labels"] and r["tier"] == "T3" for r in rows)


def test_gap_only_after_the_lag_exceeds_gap_after_sec():
    from drainerwatch.db import meta_get, meta_set
    ctx = make_ctx()
    meta_set(ctx.conn, "cursor:eth", 1000)
    assert scan.plan_range(ctx.conn, "eth", 1150, 100) == (1001, 1100)          # 148 behind, 45 min = 225 blocks: no gap
    assert not meta_get(ctx.conn, "gaps:eth")
    assert scan.plan_range(ctx.conn, "eth", 1400, 100) == (1299, 1398)          # 398 behind: gap 1001-1298
    assert json.loads(meta_get(ctx.conn, "gaps:eth"))[0]["to"] == 1298
