"""Web-research rules W1-W13: synthetic receipts / blocks for every rule, negatives for the guards, tier policy
(never T1 from one heuristic)."""
import json

import pytest

from drainerwatch import bytecode, detectors, rollup, scan, wrules, wscan
from drainerwatch.constants import (LEGIT_7702_DELEGATES, LEGIT_VANITY, TOPIC_APPROVAL_ALL, TOPIC_AUTH_USED, TOPIC_OWNERSHIP_TRANSFERRED,
                                    TOPIC_P2_PERMIT, TOPIC_SAFE_ADDED_OWNER, TOPIC_SAFE_CHANGED_THRESHOLD,
                                    TOPIC_SEAPORT_FULFILLED, TOPIC_TRANSFER)
from drainerwatch.db import add_evidence
from drainerwatch.rpc import split_receipts
from drainerwatch.seeds import SeedSet
from drainerwatch.util import selector
from tests.helpers import FakeRpc, a, approval_log, make_ctx, pad, transfer_log, tx_hash
from tests.test_kits_k import KitRpc, dispatcher, run_blocks, tx

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
NFT = a(0x4F4F)
CODE = "0x" + "60806040" * 40
VAN = "0x0000" + "ab" * 16 + "0000"                 # vanity contract address
V = lambda i: a(0xABC000 + i)  # noqa: E731
SAFE_CODE = ("0x608060405273ffffffffffffffffffffffffffffffffffffffff600054167fa619486e000000000000000000000000000000000000000"
             "0000000000000000000000060003514156050578060005260206000f35b3660008037600080366000845af43d6000803e600081141560"
             "70573d6000fd5b3d6000f3fe")
TOKEN_LIKE = dispatcher(["a9059cbb", "23b872dd", "095ea7b3", "70a08231"], tail="f4")    # ERC-20 dispatcher + DELEGATECALL


@pytest.fixture(autouse=True)
def no_etherscan(monkeypatch):
    monkeypatch.setattr(wscan, "etherscan", lambda ctx: None)


def lg(h, addr, topics, data="0x", block=100, li=0):
    return dict(transactionHash=h, logIndex=hex(li), blockNumber=hex(block), address=addr, topics=topics, data=data)


def w(x):
    return f"{x:064x}" if isinstance(x, int) else "0" * 24 + x[2:]


def rc(h, frm, to, logs, blk=100, created=None):
    return {"transactionHash": h, "from": frm, "to": to, "blockNumber": hex(blk), "contractAddress": created,
            "status": "0x1", "logs": logs}


def run(receipts, codes=None, nonces=None, rpc=None, ctx=None):
    logs, meta = split_receipts(receipts)
    ctx = ctx or make_ctx(rpc or FakeRpc(codes=codes or {}, symbols={USDT: ("USDT", 6)}, nonces=nonces or {}))
    blocks = [m["block"] for m in meta.values()]
    scan.process_chunk(ctx, min(blocks), max(blocks), logs, txmeta=meta)
    return ctx, {r["address"]: r for r in rollup.rollup(ctx.conn, SeedSet(), {})}


def ev(ctx, type_):
    return [json.loads(r[0]) for r in ctx.conn.execute("SELECT detail FROM evidence WHERE type=?", (type_,))]


# ---------- helpers ----------
def test_vanity_grid_lookalike_and_code_traits():
    assert wrules.is_vanity(VAN) and wrules.is_vanity("0x00000f312c54d0dd25888ee9cdc3dee988700000")
    assert not wrules.is_vanity("0x000" + "ab" * 16 + "a0000") and not wrules.is_vanity("0x0000" + "ab" * 17 + "000")
    assert wrules.is_vanity("0x0000" + "cd" * 16 + "0000") and "0x00000000f9490004c11cef243f5400493c00ad63" in LEGIT_VANITY
    assert wrules.grid_share(0.802) == 0.80 and wrules.grid_share(0.851) == 0.85 and wrules.grid_share(0.76) is None
    assert wrules.grid_share(0.98) is None and wrules.grid_share(None) is None
    r = "0x1a2b3c" + "0" * 30 + "dead"
    assert wrules.lookalike(r, "0x1a2" + "f" * 33 + "dead") and not wrules.lookalike(r, r)
    assert not wrules.lookalike(r, "0x1a3" + "f" * 33 + "dead") and not wrules.lookalike(r, "0x1a2" + "f" * 33 + "deaf")
    info = bytecode.analyze(SAFE_CODE)
    assert info["safe_proxy"] and info["delegatecall"] and not info["erc20_like"]
    info = bytecode.analyze(TOKEN_LIKE)
    assert info["erc20_like"] and info["delegatecall"] and not info["safe_proxy"]
    assert not bytecode.analyze(dispatcher(["a9059cbb", "23b872dd", "095ea7b3", "70a08231"]))["delegatecall"]


def test_tier_policy_never_t1_from_one_w_heuristic():
    t = detectors.assign_tier
    for one in detectors.W_T2:
        assert t({one}, 5, True) == "T2"
    for one in detectors.W_T3:
        assert t({one}, 5, True) == "T3"
    assert t({"deploy_drain", "owner_takeover"}, 1, True) == "T1"          # two different W rules
    assert t({"vanity_drainer"}, 5, True) == "T2"                          # approvals only
    assert t({"vanity_drainer", "bait_forward"}, 2, True) == "T1"          # vanity prior + behaviour, 2 victims
    assert t({"vanity_drainer", "bait_forward"}, 1, True) == "T2"
    assert t({"eip7702_batch", "eip7702_chain0"}, 0, True) == "T2"
    assert t({"share_grid"}, 1, True) is None and t({"kept_share"}, 1, True) is None


# ---------- W2 vanity ----------
def test_w2_vanity_approvals_from_three_eoas():
    rcs = [rc(tx_hash(i), V(i), USDT, [approval_log(tx_hash(i), USDT, V(i), VAN, 2 ** 256 - 1)]) for i in (1, 2, 3)]
    ctx, rows = run(rcs, codes={VAN: CODE})
    assert rows[VAN]["tier"] == "T2" and "vanity_drainer" in rows[VAN]["labels"] and rows[VAN]["victims"] == 3
    other = a(0xBEEF)                                   # same approvals to a non-vanity spender: nothing
    rcs = [rc(tx_hash(10 + i), V(i), USDT, [approval_log(tx_hash(10 + i), USDT, V(i), other, 5)]) for i in (1, 2, 3)]
    _, rows = run(rcs, codes={other: CODE})
    assert other not in rows
    rcs = [rc(tx_hash(20 + i), V(i), USDT, [approval_log(tx_hash(20 + i), USDT, V(i), VAN, 5)]) for i in (1, 2)]
    _, rows = run(rcs, codes={VAN: CODE})
    assert VAN not in rows                              # 2 approvers, no behaviour: a prior only


# ---------- W1 deploy-and-drain ----------
def test_w1a_toplevel_creation_moves_third_party_tokens():
    c, dep = a(0xC0DE), a(0xD0D0)
    h = tx_hash(1)
    ctx, rows = run([rc(h, dep, None, [transfer_log(h, USDT, V(1), a(0xEE), 50_000_000)], created=c)],
                    codes={c: CODE})
    r = rows[c]
    assert r["tier"] == "T2" and r["labels"] == ["deploy_drain"] and r["victims"] == 1
    assert dict(ctx.conn.execute("SELECT wallet, role FROM payouts").fetchall()) == {dep: "deployer"}
    # the deployer moving its own tokens in its creation tx (liquidity, funding) is not a drain
    h2 = tx_hash(2)
    _, rows = run([rc(h2, dep, None, [transfer_log(h2, USDT, dep, c, 50_000_000)], created=a(0xC0DF))])
    assert not rows


class CodeAtRpc(FakeRpc):
    def __init__(self, before=None, **kw):
        super().__init__(**kw)
        self.before = before or {}

    def code_at(self, pairs):
        return {p: self.before.get(p[0]) for p in pairs}


def _permit_pull(before):
    child, factory, op = a(0xC1), a(0xFA), a(0x0B)
    h = tx_hash(5)
    logs = [approval_log(h, USDT, V(1), child, 10 ** 12, li=0), transfer_log(h, USDT, V(1), a(0xEE), 70_000_000, li=1)]
    rpc = CodeAtRpc(before={child: before}, codes={factory: CODE, child: CODE}, symbols={USDT: ("USDT", 6)})
    return child, factory, run([rc(h, op, factory, logs)], rpc=rpc)


def test_w1b_permit_used_by_a_spender_created_in_the_same_tx():
    child, factory, (ctx, rows) = _permit_pull("0x")
    assert rows[child]["tier"] == "T2" and rows[factory]["tier"] == "T2"
    (d,) = [x for x in ev(ctx, "deploy_drain") if x.get("role") != "factory"]
    assert d["via"] == "factory" and d["factory"] == factory and d["created_check"] == "archive"
    _, _, (_, rows) = _permit_pull(CODE)              # the spender existed before: an ordinary relayed permit
    assert not rows
    _, _, (ctx, rows) = _permit_pull(None)           # no recent state, no Etherscan: unknown, nothing flagged
    assert not rows and ctx.stats["w1_unknown"] == 1


def test_w1c_ghost_forwarder():
    fwd, op = a(0xFA), a(0x0B)
    ghosts = [a(0x6001), a(0x6002)]
    rcs = [rc(tx_hash(30 + i), op, fwd, [transfer_log(tx_hash(30 + i), USDT, g, a(0xEE), 90_000_000)])
           for i, g in enumerate(ghosts)]
    ctx, rows = run(rcs[:1], codes={fwd: CODE}, nonces={g: 0 for g in ghosts})
    assert rows[fwd]["tier"] == "T3" and rows[fwd]["labels"] == ["ghost_forward"]
    ctx, rows = run(rcs[1:], ctx=ctx)
    assert rows[fwd]["tier"] == "T3" and "ghost_forward_multi" in rows[fwd]["labels"]    # counterfactual deposit forwarders look the same
    # guards: the address has sent txs (approved earlier), an Approval by it in the tx, an EIP-3009 authorization
    _, rows = run(rcs[:1], codes={fwd: CODE}, nonces={ghosts[0]: 4})
    assert not rows
    h = tx_hash(40)
    _, rows = run([rc(h, op, fwd, [approval_log(h, USDT, ghosts[0], fwd, 0, li=0),
                                   transfer_log(h, USDT, ghosts[0], a(0xEE), 90_000_000, li=1)])],
                  codes={fwd: CODE}, nonces={ghosts[0]: 0})
    assert not rows
    h = tx_hash(41)
    _, rows = run([rc(h, op, fwd, [transfer_log(h, USDT, ghosts[0], a(0xEE), 90_000_000, li=0),
                                   lg(h, USDT, [TOPIC_AUTH_USED, pad(ghosts[0]), "0x" + "11" * 32], li=1)])],
                  codes={fwd: CODE}, nonces={ghosts[0]: 0})
    assert not rows


# ---------- W3 bait forward ----------
def _bait(victims, after, before=0, to=a(0xBA17), sel="143087ee", value=10 ** 18):
    txs = {100: [tx(tx_hash(50 + i), V(i), to, "0x" + sel, value) for i in range(victims)]}
    bal = {(to, 99): before, (to, 100): after}
    return run_blocks(txs, codes={to: dispatcher(["a9059cbb"])}, balances=bal)


def test_w3_bait_forward_balance_delta_and_kept_share():
    to = a(0xBA17)
    ctx, rows = _bait(1, after=0)
    r = rows[to]
    assert r["tier"] == "T3" and {"bait_forward", "redflag_payable"} <= set(r["labels"])
    (d,) = ev(ctx, "bait_forward")
    assert d["forwarded_share"] == 1.0 and d["via"] == "balance_delta" and not d["in_dispatch"]
    _, rows = _bait(2, after=0)
    assert rows[to]["tier"] == "T2" and "bait_forward_multi" in rows[to]["labels"]
    ctx, rows = _bait(1, after=2 * 10 ** 17)              # 80 % forwarded, 20 % kept (DaaS fee stays in the contract)
    (d,) = ev(ctx, "bait_forward")
    assert d["kept_share"] == 0.2 and "kept_share" in rows[to]["labels"]
    ctx, rows = _bait(1, after=10 ** 18)                  # everything stayed: nothing forwarded
    assert not ev(ctx, "bait_forward")
    van = VAN                                            # any selector on a vanity contract, 2 victims: T1
    _, rows = _bait(2, after=0, to=van, sel="deadbeef")
    assert rows[van]["tier"] == "T1" and {"vanity_drainer", "bait_forward_multi"} <= set(rows[van]["labels"])


# ---------- W4 token-like spender ----------
def test_w4_token_like_spender_with_delegatecall():
    s, op = a(0x70C3), a(0x0B)
    rcs = [rc(tx_hash(60 + i), op, s, [transfer_log(tx_hash(60 + i), USDT, V(i), a(0xEE), 30_000_000)]) for i in (1, 2)]
    _, rows = run(rcs[:1], codes={s: TOKEN_LIKE})
    assert rows[s]["tier"] == "T3" and rows[s]["labels"] == ["token_spender_pull"]
    _, rows = run(rcs, codes={s: TOKEN_LIKE})
    assert rows[s]["tier"] == "T2" and "token_spender_multi" in rows[s]["labels"]
    _, rows = run(rcs, codes={s: dispatcher(["a9059cbb", "23b872dd", "095ea7b3", "70a08231"])})   # no DELEGATECALL
    assert s not in rows or "token_spender_pull" not in rows[s]["labels"]
    h = tx_hash(70)                                     # vault deposit shape: shares minted in the same tx
    _, rows = run([rc(h, op, s, [transfer_log(h, USDT, V(1), s, 30_000_000, li=0),
                                 transfer_log(h, s, "0x" + "0" * 40, V(1), 5, li=1)])], codes={s: TOKEN_LIKE})
    assert s not in rows or "token_spender_pull" not in rows[s]["labels"]


# ---------- W5 owner takeover ----------
def _takeover(new_nonce=2, prev=None, signer=None):
    proxy, new = a(0x9A0), a(0x9E3)
    prev = prev or V(1)
    h1, h2 = tx_hash(80), tx_hash(81)
    rcs = [rc(h1, signer or V(1), proxy, [lg(h1, proxy, [TOPIC_OWNERSHIP_TRANSFERRED, pad(prev), pad(new)])]),
           rc(h2, new, proxy, [transfer_log(h2, USDT, proxy, a(0xEE), 500_000_000)], blk=101)]
    return proxy, new, run(rcs, codes={proxy: CODE}, nonces={new: new_nonce})


def test_w5_owner_takeover_then_outflow_by_new_owner():
    proxy, new, (ctx, rows) = _takeover()
    assert rows[new]["tier"] == "T2" and rows[new]["labels"] == ["owner_takeover"]
    (d,) = ev(ctx, "owner_takeover")
    assert d["contract"] == proxy and d["victim"] == V(1) and d["kind"] == "ownership"
    _, new, (_, rows) = _takeover(new_nonce=900)        # long-lived new owner: an ordinary handover
    assert new not in rows
    _, new, (_, rows) = _takeover(prev="0x" + "0" * 40)  # construction, not a change
    assert new not in rows
    _, new, (_, rows) = _takeover(signer=a(0x9E3))      # the new owner signed it himself
    assert new not in rows


def test_w5_safe_added_owner_needs_control_change():
    safe, new = a(0x5AF), a(0x9E4)
    h1, h2 = tx_hash(90), tx_hash(91)
    added = lg(h1, safe, [TOPIC_SAFE_ADDED_OWNER], "0x" + w(new), li=0)
    thr = lg(h1, safe, [TOPIC_SAFE_CHANGED_THRESHOLD], "0x" + w(1), li=1)
    out = rc(h2, new, safe, [transfer_log(h2, USDT, safe, a(0xEE), 500_000_000)], blk=101)
    _, rows = run([rc(h1, V(1), safe, [added, thr]), out], codes={safe: CODE}, nonces={new: 1})
    assert rows[new]["tier"] == "T2"
    _, rows = run([rc(h1, V(1), safe, [added]), out], codes={safe: CODE}, nonces={new: 1})
    assert new not in rows                               # co-signer added, threshold unchanged: administration


# ---------- W6 Safe proxy spender ----------
def test_w6_safe_proxy_spender_of_many_victims():
    safe, op = a(0x5A5), a(0x0B)
    rcs = [rc(tx_hash(100 + i), V(i), USDT, [approval_log(tx_hash(100 + i), USDT, V(i), safe, 10 ** 30)]) for i in (1, 2)]
    p2 = tx_hash(103)
    rcs.append(rc(p2, V(3), a(0x22d4), [lg(p2, a(0x22d4), [TOPIC_P2_PERMIT, pad(V(3)), pad(USDT), pad(safe)],
                                       "0x" + w(10 ** 30) + w(1) + w(0))]))
    ctx, rows = run(rcs, codes={safe: SAFE_CODE})
    assert rows[safe]["tier"] == "T3" and rows[safe]["labels"] == ["safe_spender"]
    h = tx_hash(104)
    _, rows = run([rc(h, op, safe, [transfer_log(h, USDT, V(1), a(0xEE), 40_000_000)])], ctx=ctx)
    assert rows[safe]["tier"] == "T2" and "safe_spender_pull" in rows[safe]["labels"]


# ---------- W7 NFT ----------
def order_fulfilled(h, offerer, recipient, offer, cons, seaport=a(0x5EA)):
    """offer: [(type, token, id, amount)]; cons: [(type, token, id, amount, recipient)]."""
    head = 4 * 32
    off_o = head
    off_c = off_o + 32 + 128 * len(offer)
    data = w(1) + w(recipient) + w(off_o) + w(off_c) + w(len(offer))
    data += "".join(w(t) + w(tok) + w(i) + w(n) for t, tok, i, n in offer)
    data += w(len(cons)) + "".join(w(t) + w(tok) + w(i) + w(n) + w(r) for t, tok, i, n, r in cons)
    return lg(h, seaport, [TOPIC_SEAPORT_FULFILLED, pad(offerer), pad(a(0))], "0x" + data)


def test_w7_seaport_zero_price_orders():
    ful = a(0xF111)
    logs = [order_fulfilled(tx_hash(110 + i), V(i), ful, [(2, NFT, 7 + i, 1)], [(0, a(0), 0, 10 ** 15, a(0xFEE))])
            for i in (1, 2)]
    rcs = [rc(x["transactionHash"], ful, a(0x5EA), [x]) for x in logs]
    ctx, rows = run(rcs[:1])
    assert rows[ful]["tier"] == "T3" and rows[ful]["labels"] == ["seaport_zero"]
    _, rows = run(rcs)
    assert rows[ful]["tier"] == "T2" and "seaport_zero_multi" in rows[ful]["labels"]
    paid = order_fulfilled(tx_hash(120), V(5), ful, [(2, NFT, 9, 1)], [(0, a(0), 0, 10 ** 18, V(5))])
    assert wrules.seaport_zero(wrules.decode_order_fulfilled(paid)) is None
    d = wrules.seaport_zero(wrules.decode_order_fulfilled(logs[0]))
    assert d["victim"] == V(1) and d["fulfiller"] == ful and d["n_nfts"] == 1


def test_w7_set_approval_for_all_to_eoa_then_transfers():
    op, h1, h2 = a(0x0E0A), tx_hash(130), tx_hash(131)
    appr = lg(h1, NFT, [TOPIC_APPROVAL_ALL, pad(V(1)), pad(op)], "0x" + w(1))
    nft = lg(h2, NFT, [TOPIC_TRANSFER, pad(V(1)), pad(a(0xEE)), "0x" + w(42)])
    ctx, rows = run([rc(h1, V(1), NFT, [appr]), rc(h2, op, NFT, [nft], blk=101)])
    assert rows[op]["tier"] == "T2" and rows[op]["labels"] == ["nft_operator_pull"]
    _, rows = run([rc(h1, V(1), NFT, [appr]), rc(h2, op, NFT, [nft], blk=101)], codes={op: CODE})
    assert op not in rows                                # operator is a contract (marketplace / conduit)


# ---------- W8 EIP-7702 ----------
def test_w8b_phishing_batch_through_legit_delegator():
    mm = next(iter(LEGIT_7702_DELEGATES))
    x, h = a(0xA77A), tx_hash(140)
    logs = [approval_log(h, USDT, V(1), x, 2 ** 256 - 1, li=0), transfer_log(h, USDT, V(1), x, 80_000_000, li=1)]
    ctx, rows = run([rc(h, V(1), V(1), logs)], codes={V(1): "0xef0100" + mm[2:]})
    assert rows[x]["tier"] == "T2" and "batch7702_approve" in rows[x]["labels"]
    (d,) = ev(ctx, "batch7702_approve")
    assert d["legit_delegate"] and d["victim"] == V(1)
    # an approval to a contract (router) plus a swap that pays the owner back is an ordinary batch
    r = a(0x6767)
    logs = [approval_log(h, USDT, V(1), r, 10 ** 9, li=0), transfer_log(h, USDT, V(1), r, 80_000_000, li=1),
            transfer_log(h, a(0x1111), r, V(1), 5, li=2)]
    _, rows = run([rc(h, V(1), V(1), logs)], codes={V(1): "0xef0100" + mm[2:], r: CODE})
    assert r not in rows


def test_w8a_batch_authorizations():
    d = a(0xDE1E)
    auths = [{"chainId": "0x0" if i == 0 else "0x1", "address": d, "nonce": "0x0", "yParity": "0x0", "r": "0x1",
              "s": "0x1"} for i in range(7)]
    t = dict(tx(tx_hash(150), a(0x0B), a(0x0B)), type="0x4", authorizationList=auths)
    ctx, rows = run_blocks({100: [t]}, codes={d: CODE})
    assert rows[d]["tier"] == "T2" and {"eip7702_batch", "eip7702_chain0"} <= set(rows[d]["labels"])
    (x,) = ev(ctx, "eip7702_batch")
    assert x["max_per_tx"] == 7 and x["chain0"] == 1
    t = dict(t, authorizationList=[dict(au, address=next(iter(LEGIT_7702_DELEGATES)), chainId="0x1") for au in auths])
    ctx, _ = run_blocks({100: [t]})
    assert not ev(ctx, "eip7702_batch")


# ---------- W10 zero-value poisoning ----------
def test_w10_zero_value_transfer_from_on_real_usdt():
    bundler, op = a(0xB0B0), a(0x0B)
    real = ["0x1a2b3c" + f"{i:030x}" + "dead" for i in range(3)]
    fake = ["0x1a2" + "f" * 32 + f"{i}" + "dead" for i in range(3)]
    rcs = [rc(tx_hash(160 + i), V(i), USDT, [transfer_log(tx_hash(160 + i), USDT, V(i), real[i], 5_000_000)])
           for i in range(3)]
    h = tx_hash(170)
    rcs.append(rc(h, op, bundler, [transfer_log(h, USDT, V(i), fake[i], 0, li=i) for i in range(3)], blk=101))
    ctx, rows = run(rcs, codes={bundler: CODE})
    r = rows[bundler]
    assert r["tier"] == "T3" and r["labels"] == ["poison_zero"] and r["victims"] == 0 and r["drains"] == 0
    (d,) = ev(ctx, "poison_zero")
    assert d["legs"] == 3 and d["lookalikes"] == 3


# ---------- W11 / W12 / W13 roll-up rules ----------
def test_w11_share_grid_bonus_is_score_only():
    from tests.test_kits import xsplit_chunk
    puller = a(0x9C)
    logs, meta = xsplit_chunk(V(1), [80_000_000, 20_000_000], [a(0xD1), a(0xD2)])
    ctx = make_ctx(FakeRpc(codes={puller: CODE}, symbols={USDT: ("USDT", 6)}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    (r,) = [x for x in rollup.rollup(ctx.conn, SeedSet(), {}) if x["address"] == puller]
    assert r["tier"] == "T3" and set(r["labels"]) == {"split_xtx", "share_grid"}


def _db(n_drainers, ev_type="deploy_drain", wallet=a(0x77)):
    ctx = make_ctx()
    c = ctx.conn
    for i in range(n_drainers):
        d = a(0xD000 + i)
        add_evidence(c, "eth", d, ev_type, tx_hash(200 + i), 1, 1_800_000_000, dict(victims=[V(i)], via="toplevel",
                                                                                   deployer=a(0xDEB)))
        c.execute("INSERT INTO payouts VALUES('eth',?,?,'collector',NULL,1)", (d, wallet))
        c.execute("INSERT INTO creations VALUES('eth',?,?,?,1,1)", (d, a(0xDEB), tx_hash(200 + i)))
    c.commit()
    return {r["address"]: r for r in rollup.rollup(c, SeedSet(), {})}


def test_w12_operator_wallet_and_w13_serial_deployer():
    rows = _db(3)
    assert rows[a(0x77)]["tier"] == "T2" and {"operator_wallet", "operator_wallet_multi"} <= set(rows[a(0x77)]["labels"])
    assert rows[a(0xDEB)]["tier"] == "T2" and "serial_deployer_multi" in rows[a(0xDEB)]["labels"]
    rows = _db(2)
    assert rows[a(0x77)]["tier"] == "T3" and rows[a(0x77)]["labels"] == ["operator_wallet"]
    assert rows[a(0xDEB)]["tier"] == "T3" and rows[a(0xDEB)]["labels"] == ["serial_deployer"]
    rows = _db(1)
    assert a(0x77) not in rows and a(0xDEB) not in rows


def test_w1_weak_when_victim_gets_something_back():
    child, factory, op, h = a(0xC1), a(0xFA), a(0x0B), tx_hash(6)
    logs = [approval_log(h, USDT, V(1), child, 10 ** 12, li=0), transfer_log(h, USDT, V(1), child, 70_000_000, li=1),
            transfer_log(h, a(0xA70C), "0x" + "0" * 40, V(1), 70, li=2)]          # receipt token minted to the user
    rpc = CodeAtRpc(before={child: "0x"}, codes={factory: CODE, child: CODE}, symbols={USDT: ("USDT", 6)})
    _, rows = run([rc(h, op, factory, logs)], rpc=rpc)
    assert rows[child]["tier"] == "T3" and rows[child]["labels"] == ["deploy_drain_weak"]


# ---------- regressions: capped subjects and cross-chain twins ----------
def _twins(chains, victims=1, usd=None, ev="split_pull"):
    ctx = make_ctx()
    c = ctx.conn
    x = a(0x87DC)
    for i, ch in enumerate(chains):
        add_evidence(c, ch, x, ev, tx_hash(300 + i), 1, 1_800_000_000,
                     dict(victims=[V(j) for j in range(victims)], token=a(0x70C), recipients=[
                         dict(wallet=a(0xD1), share=0.62, role="affiliate"), dict(wallet=a(0xD2), share=0.38, role="operator")]))
        c.execute("INSERT INTO codes VALUES(?,?,?,?,?,?)", (ch, x, "0xh", 500, "skel_same", "[]"))
        if usd:
            c.execute("INSERT INTO drains VALUES(?,?,0,1,?,?,?,'T',6,'1',?,?)", (ch, tx_hash(300 + i), V(0), x, a(0x70C), usd, a(0xD1)))
    c.commit()
    return x, {(r["chain"], r["address"]): r for r in rollup.rollup(c, SeedSet(), {})}


def test_cross_chain_twin_never_lifts_a_capped_subject():
    x, rows = _twins(["eth", "base", "bsc"])           # one unpriced single-victim split on each chain
    for ch in ("eth", "base", "bsc"):
        r = rows[(ch, x)]
        assert r["tier"] == "T3" and "cross_chain" in r["labels"], (ch, r)
        assert r["labels"].count("cross_chain") == 1


def test_one_victim_split_on_unverifiable_chain_is_capped():
    x, rows = _twins(["bsc"], victims=1, usd=473.0)
    assert rows[("bsc", x)]["tier"] == "T3" and "unverified_split_capped" in rows[("bsc", x)]["labels"]
    x, rows = _twins(["bsc"], victims=2, usd=20.0)
    assert rows[("bsc", x)]["tier"] == "T2"
    x, rows = _twins(["eth"], victims=1, usd=473.0)     # ETH keeps the verified-source cap path instead
    assert rows[("eth", x)]["tier"] == "T2"
