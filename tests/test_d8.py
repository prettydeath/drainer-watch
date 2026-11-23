"""D8 eoa_spender_pull: EOA operator pulls via token.transferFrom / Permit2 (receipts source only)."""
from drainerwatch import detectors, rollup, scan
from drainerwatch.constants import PERMIT2
from drainerwatch.rpc import parse_logs, split_receipts
from drainerwatch.seeds import SeedSet
from tests.helpers import FakeRpc, a, make_ctx, transfer_log, tx_hash

TOKEN = a(0xAAA)
OP, COLLECT = a(0x0B), a(0xC0)
CODE = "0x" + "60806040" * 40
V = lambda i: a(0xABC000 + i)  # noqa: E731


def rc(h, frm, to, logs, block=100):
    return {"transactionHash": h, "from": frm, "to": to, "blockNumber": hex(block), "contractAddress": None,
            "status": "0x1", "logs": logs}


def chunk(victims, spender=OP, to=None, recipient=COLLECT, block=100, token=TOKEN):
    to = to or token
    logs, rcs = [], []
    for i, v in enumerate(victims):
        h = tx_hash(1000 + i)
        lg = [transfer_log(h, token, v, recipient, 5_000_000, block=block, li=i)]
        logs += lg
        rcs.append(rc(h, spender, to, lg, block))
    return logs, split_receipts(rcs)[1]


def never(_):
    return False


def test_d8_candidates_shape():
    logs, meta = chunk([V(1)])
    tr, _ = parse_logs(logs)
    (c,) = detectors.d8_candidates(tr, meta, never)
    assert (c["spender"], c["frm"], c["to"], c["via"]) == (OP, V(1), COLLECT, "transferFrom")
    logs, meta = chunk([V(1)], to=PERMIT2)
    assert detectors.d8_candidates(parse_logs(logs)[0], meta, never)[0]["via"] == "permit2"
    # negatives: victim is the sender; recipient is the spender itself (custodial sweep to hot wallet); tx.to is a
    # contract other than the token/Permit2 (that is D2/D3 territory); labelled (legit) spender
    for kw in (dict(spender=V(1)), dict(recipient=OP)):
        logs, meta = chunk([V(1)], **kw)
        assert detectors.d8_candidates(parse_logs(logs)[0], meta, never) == []
    # tx.to another address: candidate with spender = tx.to (7702 operator account), allowlisted tx.to: nothing
    logs, meta = chunk([V(1)], to=a(0xDEAD))
    (c,) = detectors.d8_candidates(parse_logs(logs)[0], meta, never)
    assert (c["spender"], c["via"]) == (a(0xDEAD), "7702")
    assert detectors.d8_candidates(parse_logs(logs)[0], meta, lambda x: x == a(0xDEAD)) == []
    logs, meta = chunk([V(1)])
    assert detectors.d8_candidates(parse_logs(logs)[0], meta, lambda x: x == OP) == []


def test_d8_confirm_nonce_and_code_guards():
    c = dict(frm=V(1), to=COLLECT, spender=OP)
    eoa = lambda x: False  # noqa: E731
    assert detectors.d8_confirm(c, eoa, {V(1): 10, OP: 50})
    assert not detectors.d8_confirm(c, eoa, {V(1): 1, OP: 50})          # custodial deposit address
    assert not detectors.d8_confirm(c, eoa, {V(1): 10, OP: 50_000})     # high-volume sweeper
    assert not detectors.d8_confirm(c, eoa, {V(1): 10})                 # unknown nonce: no flag
    assert not detectors.d8_confirm(c, lambda x: x == COLLECT, {V(1): 10, OP: 50})   # recipient is a contract
    c7 = dict(c, via="7702")
    assert not detectors.d8_confirm(c7, eoa, {V(1): 10, OP: 50})                     # tx.to not delegated
    assert detectors.d8_confirm(c7, eoa, {V(1): 10, OP: 50}, lambda x: x == OP)


def test_d8_pipeline_tiers():
    usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    if True:
        logs, meta = chunk([V(1)], token=usdt)
        ctx = make_ctx(FakeRpc(symbols={usdt: ("USDT", 6)}))
        scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
        rows = rollup.rollup(ctx.conn, SeedSet(), {})
        assert [(r["address"], r["tier"], r["labels"]) for r in rows] == [(OP, "T3", ["eoa_spender_pull"])]
        assert ctx.conn.execute("SELECT victim, drainer, recipient FROM drains").fetchone()[:] == (V(1), OP, COLLECT)
        logs, meta = chunk([V(1), V(2), V(3)], token=usdt)
        ctx = make_ctx(FakeRpc(symbols={usdt: ("USDT", 6)}))
        scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
        (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
        assert r["tier"] == "T2" and "eoa_spender_multi" in r["labels"] and r["victims"] == 3


def test_d8_off_without_txmeta_and_custodial_victims():
    logs, meta = chunk([V(1), V(2), V(3)])
    ctx = make_ctx(FakeRpc())
    scan.process_chunk(ctx, 100, 100, logs)                                  # logs source: D8 is off
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []
    ctx = make_ctx(FakeRpc(nonces={V(1): 1, V(2): 2, V(3): 1}))            # deposit-address-like victims
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []


def test_d8_pipeline_7702_operator_account_vs_plain_contract():
    usdt = "0xdac17f958d2ee523a2206206994597c13d831ec7"
    acct, router = a(0x7702), a(0x0E0E)
    delegated = "0xef0100" + "11" * 20
    for to, code, expect in ((acct, delegated, [(acct, "T3")]), (router, CODE, [])):
        logs, meta = chunk([V(1)], to=to, token=usdt, spender=a(0x99))
        ctx = make_ctx(FakeRpc(codes={to: code}, symbols={usdt: ("USDT", 6)}))
        scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
        assert [(r["address"], r["tier"]) for r in rollup.rollup(ctx.conn, SeedSet(), {})] == expect
