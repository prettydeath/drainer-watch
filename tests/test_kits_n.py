"""kit notes N1-N11: Trusty v1 / MS_NEW public contracts (bytecode family, watchlist attribution, cashback flag),
dust-value approvals, emergency gas, ETH-in swaps, separate-tx router allowance + swap, gas constants, vanity booster,
90/10 cross-tx split, fresh generated-bait receiver."""
import json
from pathlib import Path

from drainerwatch import bytecode, detectors, rollup, scan
from drainerwatch.constants import (KIT_APPROVAL_AMOUNTS, KIT_PUBLIC_CONTRACTS, KIT_VANITY_RE, SCORE,
                                    TRUSTY_V1_SELECTORS)
from drainerwatch.render import describe
from drainerwatch.seeds import SeedSet
from drainerwatch.util import selector
from tests.helpers import FakeRpc, a, approval_log, make_ctx, tx_hash
from tests.test_kits import w, xsplit_chunk
from tests.test_kits_k import (CODE, MS_NEW_CODE, ROUTER02, TS0, USDT, V, WETH, dispatcher, gen_code, k5_run,
                               ms_new_input, run_blocks, tx, KitRpc)
from tests.test_kits import block

KITS = Path(__file__).parent / "fixtures_kits"
TRUSTY_V1 = "0x0007039b77d22042afc1a9c3b3da11837b730000"
MS_NEW_PUBLIC = "0x0000366a6afea972e4353b070ad904744a530000"
KIT_AMOUNT = next(iter(KIT_APPROVAL_AMOUNTS))
CUST, WORKER = a(0xC1C1C1), a(0xC2C2C2)


def fixture(name):
    return (KITS / name).read_text().strip()


def trusty_code():
    return fixture("trusty_v1_eth_0x0007039b77d22042afc1a9c3b3da11837b730000.hex")


def msn_code():
    return fixture("ms_new_eth_0x0000366a6afea972e4353b070ad904744a530000.hex")


def evidence(ctx, type_):
    return [json.loads(r[0]) for r in ctx.conn.execute("SELECT detail FROM evidence WHERE type=?", (type_,))]


# ---------- N2 bytecode family ----------
def test_n2_trusty_v1_family_and_public_runtime():
    info = bytecode.analyze(trusty_code())
    assert info["kit"] == "trusty_v1" and info["kit_public"] == "trusty_v1" and info["size"] == 2936
    assert set(TRUSTY_V1_SELECTORS) <= set(info["selectors"]) and len(info["redflags"]) == 8
    info = bytecode.analyze(msn_code())                     # the deployed MS_NEW classifies as K1
    assert info["kit"] == "ms_new" and info["kit_public"] == "ms_new" and info["size"] == 5436
    baits = [selector(n) for n in ("Claim(address)", "Connect(address)", "Execute(address)")]
    assert bytecode.kit_family(baits + list(TRUSTY_V1_SELECTORS)) == "trusty_v1"
    assert bytecode.kit_family(baits[:2] + list(TRUSTY_V1_SELECTORS)) is None          # < 3 bait(address)
    assert bytecode.kit_family(baits + list(TRUSTY_V1_SELECTORS)[:2]) is None          # Fee/getFee/changePercentage all needed
    assert bytecode.analyze(dispatcher(baits + list(TRUSTY_V1_SELECTORS)))["kit_public"] is None   # family, not exact code


# ---------- N3 kit public contracts ----------
def test_n3_trusty_v1_public_bait_is_t1_with_customer():
    t = tx(tx_hash(10), V(1), TRUSTY_V1, "0x" + selector("Execute(address)") + w(CUST), 10 ** 16)
    ctx, rows = run_blocks({100: [t]}, codes={TRUSTY_V1: trusty_code()})
    r = rows[TRUSTY_V1]
    assert r["tier"] == "T1" and {"kit_confirmed", "kit_public", "bait_payable"} <= set(r["labels"])
    assert r["family"] == "trusty_v1" and r["victims"] == 1
    assert dict(ctx.conn.execute("SELECT wallet, role FROM payouts").fetchall()) == {CUST: "customer"}
    (d,) = evidence(ctx, "bait_payable")
    assert d["kit"] == "trusty_v1" and d["public"] == "trusty_v1" and "Trusty v1" in describe("bait_payable", d)


def test_n3_trusty_v1_clone_same_runtime_other_address():
    clone = a(0x7777)
    t = tx(tx_hash(11), V(1), clone, "0x" + selector("Claim(address)") + w(CUST), 10 ** 16)
    _, rows = run_blocks({100: [t]}, codes={clone: trusty_code()})
    assert rows[clone]["tier"] == "T1" and "kit_confirmed" in rows[clone]["labels"]


def test_n3_ms_new_public_handler_keeper_roles():
    t = tx(tx_hash(12), V(2), MS_NEW_PUBLIC, ms_new_input("Deposit", V(2), CUST, WORKER, 30, 0), 10 ** 18)
    ctx, rows = run_blocks({100: [t]}, codes={MS_NEW_PUBLIC: msn_code()})
    r = rows[MS_NEW_PUBLIC]
    assert r["tier"] == "T1" and "kit_confirmed" in r["labels"] and "ms_cashback" not in r["labels"]
    assert dict(ctx.conn.execute("SELECT wallet, role FROM payouts").fetchall()) == {CUST: "customer", WORKER: "worker"}


def test_n3_failed_call_and_zero_value_are_ignored():
    t = tx(tx_hash(13), V(1), TRUSTY_V1, "0x" + selector("Execute(address)") + w(CUST), 0)
    assert run_blocks({100: [t]}, codes={TRUSTY_V1: trusty_code()})[1] == {}


class TxRpc(FakeRpc):
    chain = "base"


def test_n3_receipts_chain_looks_up_only_watchlisted_txs():
    h, other = tx_hash(14), tx_hash(15)
    full = {h: {"hash": h, "from": V(3), "to": MS_NEW_PUBLIC, "blockNumber": hex(100), "value": hex(10 ** 17),
                "input": ms_new_input("Claim", V(3), CUST, WORKER, 0, 1), "nonce": "0x5", "gas": hex(100_000)}}
    rpc = TxRpc(txs=full, codes={MS_NEW_PUBLIC: msn_code()})
    looked = []
    orig = rpc.txs_by_hash
    rpc.txs_by_hash = lambda hs: looked.extend(hs) or orig(hs)
    ctx = make_ctx(rpc, chain="base")
    meta = {h: {"from": V(3), "to": MS_NEW_PUBLIC, "block": 100, "created": None, "status": 1},
            other: {"from": V(4), "to": a(0x1234), "block": 100, "created": None, "status": 1}}
    scan.process_chunk(ctx, 100, 100, [], txmeta=meta)
    assert looked == [h]
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["address"] == MS_NEW_PUBLIC and r["chain"] == "base" and r["tier"] == "T1"
    assert {"kit_confirmed", "ms_cashback"} <= set(r["labels"])


# ---------- N1 cashback flag ----------
def test_n1_cashback_with_kit_dispatcher_is_t1():
    msn = a(0x5E5E5E)
    t = tx(tx_hash(20), V(1), msn, ms_new_input("Claim", V(1), CUST, WORKER, 0, 1), 10 ** 17)
    ctx, rows = run_blocks({100: [t]}, codes={msn: MS_NEW_CODE})
    assert rows[msn]["tier"] == "T1" and "ms_cashback" in rows[msn]["labels"]
    (d,) = evidence(ctx, "bait_payable")
    assert d["cashback"] is True and "is_cashback" in describe("bait_payable", d)
    t0 = tx(tx_hash(21), V(1), msn, ms_new_input("Claim", V(1), CUST, WORKER, 0, 0), 10 ** 17)
    _, rows = run_blocks({100: [t0]}, codes={msn: MS_NEW_CODE})
    assert rows[msn]["tier"] == "T2" and "ms_cashback" not in rows[msn]["labels"]


def test_n1_cashback_calldata_without_kit_code_is_t2():
    proxy = a(0x5F5F)
    t = tx(tx_hash(22), V(1), proxy, ms_new_input("Claim", V(1), CUST, WORKER, 0, 1), 10 ** 17)
    _, rows = run_blocks({100: [t]}, codes={proxy: CODE})
    assert rows[proxy]["tier"] == "T2" and "ms_cashback_shape" in rows[proxy]["labels"]


# ---------- N4 dust-value approvals ----------
def approve_input(fn, spender, amount):
    return "0x" + selector(f"{fn}(address,uint256)") + w(spender) + w(amount)


def test_n4_dust_approve_tiers():
    sp = a(0xD0D0D0)
    t = tx(tx_hash(30), V(1), USDT, approve_input("approve", sp, 2 ** 256 - 1), 3)
    ctx, rows = run_blocks({100: [t]})
    assert rows[sp]["tier"] == "T2" and rows[sp]["labels"] == ["dust_approve"]
    (d,) = evidence(ctx, "dust_approve")
    assert d["victim"] == V(1) and d["amount"] == "max" and "wei attached" in describe("dust_approve", d)
    for fn in ("increaseAllowance", "increaseApproval"):
        t = tx(tx_hash(31), V(1), USDT, approve_input(fn, sp, KIT_AMOUNT), 1)
        _, rows = run_blocks({100: [t]})
        assert rows[sp]["tier"] == "T1" and "dust_approve_kit" in rows[sp]["labels"], fn
    for value, spender in ((0, sp), (9, sp), (3, ROUTER02)):            # no value / above 8 wei / allowlisted spender
        t = tx(tx_hash(32), V(1), USDT, approve_input("approve", spender, 10 ** 6), value)
        assert run_blocks({100: [t]})[1] == {}, (value, spender)
    assert detectors.decode_approve(approve_input("approve", sp, 5)) == dict(fn="approve", spender=sp, amount=5)
    assert detectors.decode_approve("0x" + selector("approve(address,uint256)") + "f" * 64 + w(1)) is None


# ---------- N5 emergency gas ----------
def egas_run(spender_is_funder=True, value=5 * 10 ** 15, amount=10 ** 6, gap=10, seeds=None, nonces=None):
    op, vic = a(0xE6A5E6), V(9)
    spender = op if spender_is_funder else a(0x5EED5E)
    gift = tx(tx_hash(40), op, vic, "0x", value, gas=21_000)
    appr = tx(tx_hash(41), vic, USDT, approve_input("approve", spender, amount))
    logs = [approval_log(tx_hash(41), USDT, vic, spender, amount, block=100 + gap)]
    blocks = {100: [gift], 100 + gap: [appr]}
    lo, hi = min(blocks), max(blocks)
    bl = [block(n, blocks.get(n, [])) for n in range(lo, hi + 1)]
    rpc = KitRpc(bl, symbols={USDT: ("USDT", 6)}, nonces=nonces)
    ctx = make_ctx(rpc, seeds=seeds)
    m = {t["hash"]: {"from": t["from"], "to": t["to"], "block": n, "created": None, "status": 1}
         for n, ts in blocks.items() for t in ts}
    scan.process_chunk(ctx, lo, hi, logs, txmeta=m)
    scan.eth_block_pass(ctx, lo, hi, txmeta=m)
    return ctx, op, {r["address"]: r for r in rollup.rollup(ctx.conn, SeedSet(), {})}


def test_n5_emergency_gas():
    ctx, op, rows = egas_run()                                          # self-approval: weak lead
    assert rows[op]["tier"] == "T3" and rows[op]["labels"] == ["emergency_gas_self"]
    (d,) = evidence(ctx, "emergency_gas")
    assert d["self_approval"] and d["spender_is_funder"] and d["fund_tx"] == tx_hash(40) and "within 30 min" in describe("emergency_gas", d)
    _, op, rows = egas_run(amount=KIT_AMOUNT)
    assert rows[op]["tier"] == "T1" and "emergency_gas_kit" in rows[op]["labels"]
    _, op, rows = egas_run(nonces={a(0xE6A5E6): 50_000})                # custodial sweeper funding a deposit address
    assert op not in rows
    _, op, rows = egas_run(nonces={V(9): 1})                            # deposit address (nonce 1)
    assert op not in rows
    _, op, rows = egas_run(spender_is_funder=False)                     # unrelated, unflagged spender
    assert op not in rows
    _, op, rows = egas_run(spender_is_funder=False, seeds=SeedSet([(a(0x5EED5E), None, "t", "test")]))
    assert rows[op]["tier"] == "T2" and "emergency_gas" in rows[op]["labels"]   # flagged (seed) spender
    _, op, rows = egas_run(value=10 ** 18)                              # 2 000 USD is no gas gift
    assert op not in rows
    _, op, rows = egas_run(gap=200)                                     # 40 min later
    assert op not in rows


# ---------- N6 ETH-in swap ----------
PANCAKE_V2_ETH = "0xeff92a263d31888d860bd50809a8d171709b7b1c"


def eth_in_swap(amount_out_min, path, to, deadline, sel="swapExactETHForTokens(uint256,address[],address,uint256)"):
    return ("0x" + selector(sel) + w(amount_out_min) + w(0x80) + w(to) + w(deadline) + w(len(path))
            + "".join(w(p) for p in path))


def test_n6_swap_exact_eth_for_tokens_kit_deadline():
    rcpt = a(0xFE1FE1)
    inp = eth_in_swap(0, [WETH, USDT], rcpt, TS0 + 100 + 99_990)
    (s,) = detectors.decode_swaps(inp, 10 ** 18)
    assert (s["amount_in"], s["amount_out_min"], s["to"], s["path"]) == (10 ** 18, 0, rcpt, [WETH, USDT])
    ctx, rows = run_blocks({100: [tx(tx_hash(50), V(1), PANCAKE_V2_ETH, inp, 10 ** 18, gas=350_000)]})
    r = rows[rcpt]
    assert {"foreign_recipient_swap", "foreign_swap_kit"} <= set(r["labels"]) and r["tier"] == "T2"
    (d,) = evidence(ctx, "foreign_recipient_swap")
    assert d["kit"] and d["token"] == WETH and d["router"] == PANCAKE_V2_ETH
    fot = eth_in_swap(0, [WETH, USDT], rcpt, TS0 + 100 + 99_990,
                      "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)")
    assert detectors.decode_swaps(fot, 5)[0]["amount_in"] == 5
    assert run_blocks({100: [tx(tx_hash(51), V(1), PANCAKE_V2_ETH, eth_in_swap(1, [WETH, USDT], rcpt, TS0), 10 ** 18)]})[1] == {}
    assert run_blocks({100: [tx(tx_hash(52), V(1), PANCAKE_V2_ETH, eth_in_swap(0, [WETH, USDT], V(1), TS0), 10 ** 18)]})[1] == {}


# ---------- N7 kit allowance to a router, then a swap in another tx ----------
def v2_swap_input(amount_in, rcpt, deadline):
    return ("0x" + selector("swapExactTokensForETH(uint256,uint256,address[],address,uint256)") + w(amount_in) + w(0)
            + w(0xA0) + w(rcpt) + w(deadline) + w(2) + w(USDT) + w(WETH))


def test_n7_kit_router_allowance_then_swap_separate_tx():
    rcpt = a(0xFE2FE2)
    inc = tx(tx_hash(60), V(1), USDT, approve_input("increaseAllowance", ROUTER02, KIT_AMOUNT))
    swap = tx(tx_hash(61), V(1), ROUTER02, v2_swap_input(10 ** 9, rcpt, TS0 + 120 + 99_990))
    ctx, rows = run_blocks({100: [inc], 120: [swap]})
    r = rows[rcpt]
    assert r["tier"] == "T1" and {"kit_router_swap", "foreign_recipient_swap"} <= set(r["labels"])
    (d,) = evidence(ctx, "kit_router_swap")
    assert d["xtx"] and d["approval_tx"] == tx_hash(60) and d["approval_sec_before"] == 20
    assert "legitimate router the kit allowance" in describe("kit_router_swap", d)
    _, rows = run_blocks({100: [inc], 500: [tx(tx_hash(62), V(1), ROUTER02, v2_swap_input(10 ** 9, rcpt, TS0 + 500))]})
    assert "kit_router_swap" not in rows[rcpt]["labels"]                # 400 s later: no link
    other = tx(tx_hash(63), V(2), ROUTER02, v2_swap_input(10 ** 9, rcpt, TS0 + 120))
    _, rows = run_blocks({100: [inc], 120: [other]})
    assert "kit_router_swap" not in rows[rcpt]["labels"]                # another signer
    normal = tx(tx_hash(64), V(1), USDT, approve_input("increaseAllowance", ROUTER02, 10 ** 9))
    _, rows = run_blocks({100: [normal], 120: [swap]})
    assert "kit_router_swap" not in rows[rcpt]["labels"]                # ordinary amount


# ---------- N8 gas constants ----------
def test_n8_return_gas_30000_and_deposit_gas_150000():
    hub = a(0x4B4B)
    _, rows = k5_run([{"ret_gas": 30_000}])
    assert "oneshot_hub" in rows[hub]["labels"]
    _, rows = k5_run([{"ret_gas": 30_001}])
    assert "oneshot_hub" not in rows.get(hub, {}).get("labels", [])
    msn, dep = a(0x5E5E5E), V(7)
    t = tx(tx_hash(70), dep, msn, ms_new_input("Deposit", dep, CUST, WORKER), 98 * 10 ** 16, nonce=1, gas=150_000)
    _, rows = run_blocks({100: [t]}, codes={msn: MS_NEW_CODE}, balances={(dep, 99): 10 ** 18})
    assert "kit_deposit" in rows[msn]["labels"]


# ---------- N9 vanity booster ----------
def test_n9_vanity_only_boosts_kit_subjects():
    assert KIT_VANITY_RE.match(TRUSTY_V1) and KIT_VANITY_RE.match(MS_NEW_PUBLIC)
    assert not KIT_VANITY_RE.match(a(0x5E5E5E)) and not KIT_VANITY_RE.match("0x0010000000000000000000000000000000000000")
    van = "0x000abc000000000000000000000000000000" + "0000"
    assert KIT_VANITY_RE.match(van)
    t = tx(tx_hash(80), V(1), van, ms_new_input("Claim", V(1), CUST, WORKER), 10 ** 17)
    _, rows = run_blocks({100: [t]}, codes={van: MS_NEW_CODE})
    msn = a(0x5E5E5E)
    _, plain = run_blocks({100: [tx(tx_hash(80), V(1), msn, ms_new_input("Claim", V(1), CUST, WORKER), 10 ** 17)]},
                          codes={msn: MS_NEW_CODE})
    assert "kit_vanity" in rows[van]["labels"] and rows[van]["tier"] == plain[msn]["tier"]
    assert rows[van]["score"] == min(100, plain[msn]["score"] + SCORE["kit_vanity"])
    # a vanity address with only behavioural evidence and no kit code gets no booster
    sp = "0x000def000000000000000000000000000000" + "0000"
    _, rows = run_blocks({100: [tx(tx_hash(81), V(1), USDT, approve_input("approve", sp, 10 ** 6), 3)]})
    assert "kit_vanity" not in rows[sp]["labels"]
    assert detectors.assign_tier({"kit_vanity"}, 0, False) is None


# ---------- N10 donation pull split 90/10 across two txs ----------
def test_n10_two_consecutive_transfer_from_90_10_is_split_xtx():
    op = a(0x0B)
    logs, meta = xsplit_chunk(V(1), [90_000_000, 10_000_000], [a(0xD1), a(0xD2)], caller=op, to=None)
    ctx = make_ctx(FakeRpc(codes={}, symbols={USDT: ("USDT", 6)}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    (r,) = [x for x in rollup.rollup(ctx.conn, SeedSet(), {}) if x["address"] == op]
    assert "split_xtx" in r["labels"]
    pay = dict((w_, (role, s)) for w_, role, s in ctx.conn.execute("SELECT wallet, role, share FROM payouts WHERE drainer=?",
                                                                    (op,)))
    assert pay == {a(0xD1): ("affiliate", 0.9), a(0xD2): ("operator", 0.1)}


# ---------- N11 generated bait with a fresh main receiver ----------
class NonceRpc(KitRpc):
    def __init__(self, *args, nonce_map=None, **kw):
        super().__init__(*args, **kw)
        self.nonce_map = nonce_map or {}


def test_n11_generated_bait_fresh_main_receiver():
    gen, main, fee = a(0x6E6E), a(0xAA01), a(0xFEE1)
    slot2 = int(fee, 16) | (10 << 160) | (1 << 168)
    victim = tx(tx_hash(90), V(1), gen, "0x" + selector("Claim()"), 10 ** 18)
    for nonce, fresh in ((0, True), (4, False)):
        _ctx, _ = run_blocks({100: [victim]}, codes={gen: gen_code()}, rpc_cls=NonceRpc,
                             storage={(gen, 1): int(main, 16), (gen, 2): slot2}, nonce_map={main: nonce})
        (d,) = evidence(_ctx, "bait_payable")
        assert d["main_receiver_nonce"] == nonce and d["main_receiver_fresh"] is fresh


def test_public_contract_constants():
    assert set(KIT_PUBLIC_CONTRACTS) == {TRUSTY_V1, MS_NEW_PUBLIC}
    assert TRUSTY_V1_SELECTORS == {"32b80676": "Fee(address)", "ced72f87": "getFee()",
                                   "d285660d": "changePercentage(uint8)"}
