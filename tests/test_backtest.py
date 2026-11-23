"""Receipts source, incident classification / split, backtest helpers."""
from drainerwatch import backtest, incidents, rollup, scan
from drainerwatch.rpc import split_receipts
from drainerwatch.seeds import SeedSet
from tests.helpers import FakeRpc, a, approval_log, make_ctx, transfer_log, tx_hash

TOKEN = a(0xAAA)
CODE = "0x" + "60806040" * 40
OP, AFF, DRAINER, ATTACKER = a(2), a(3), a(4), a(5)


def receipt(h, frm, to, logs, block=100, created=None, status="0x1"):
    return {"transactionHash": h, "from": frm, "to": to, "blockNumber": hex(block), "contractAddress": created,
            "status": status, "logs": logs}


def test_split_receipts_filters_topics_and_keeps_every_tx():
    h1, h2 = tx_hash(1), tx_hash(2)
    other = dict(transfer_log(h1, TOKEN, a(9), a(10), 1), topics=["0x" + "ab" * 32])
    rc = [receipt(h1, ATTACKER, DRAINER, [transfer_log(h1, TOKEN, a(9), OP, 5), other]),
          receipt(h2, a(7), None, [], created=a(0xC0))]
    logs, meta = split_receipts(rc)
    assert len(logs) == 1 and logs[0]["topics"][0] != other["topics"][0]
    assert meta[h1]["from"] == ATTACKER and meta[h1]["to"] == DRAINER
    assert meta[h2]["to"] is None and meta[h2]["created"] == a(0xC0)


def test_process_chunk_with_txmeta_needs_no_tx_lookups():
    v = a(0xABC000)
    h = tx_hash(1)
    logs = [transfer_log(h, TOKEN, v, OP, 2000), transfer_log(h, TOKEN, v, AFF, 8000, li=1)]

    class NoLookups(FakeRpc):
        def txs_by_hash(self, hashes):
            raise AssertionError("tx lookup in receipts mode")

    ctx = make_ctx(NoLookups(codes={DRAINER: CODE}))
    _, meta = split_receipts([receipt(h, ATTACKER, DRAINER, logs)])
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    rows = rollup.rollup(ctx.conn, SeedSet(), {})
    assert [(r["address"], r["tier"]) for r in rows] == [(DRAINER, "T2")]


def test_classify_pull_roles_and_patterns():
    seed, v = a(0x5EED), a(0xABC001)
    eoa = lambda x: x not in (DRAINER, TOKEN)  # noqa: E731
    no_spoof = lambda t: False  # noqa: E731
    h = tx_hash(3)
    # drainer contract pulls victim -> seed payout
    r = receipt(h, ATTACKER, DRAINER, [transfer_log(h, TOKEN, v, seed, 10)])
    (leg,) = incidents.classify(r, seed, eoa, no_spoof)
    assert (leg["role"], leg["pattern"]) == ("payout", "pull_via_contract")
    # seed is the operator EOA calling token.transferFrom directly
    r = receipt(h, seed, TOKEN, [transfer_log(h, TOKEN, v, OP, 10)])
    (leg,) = incidents.classify(r, seed, eoa, no_spoof)
    assert (leg["role"], leg["pattern"]) == ("operator", "eoa_transferFrom")
    # victim signed the tx itself -> not a pull; failed tx -> nothing; contract 'victim' -> nothing
    assert incidents.classify(receipt(h, v, DRAINER, [transfer_log(h, TOKEN, v, seed, 10)]), seed, eoa, no_spoof) == []
    assert incidents.classify(receipt(h, ATTACKER, DRAINER, [transfer_log(h, TOKEN, v, seed, 10)], status="0x0"),
                              seed, eoa, no_spoof) == []
    assert incidents.classify(receipt(h, ATTACKER, DRAINER, [transfer_log(h, TOKEN, DRAINER, seed, 10)]),
                              seed, eoa, no_spoof) == []


def test_assign_splits_keeps_components_together_and_is_deterministic():
    rows = [dict(seed_address=a(1), drainer=a(100)), dict(seed_address=a(2), drainer=a(100)),
            dict(seed_address=a(3), drainer="")] + [dict(seed_address=a(10 + i), drainer="") for i in range(40)]
    s1 = [r["split"] for r in incidents.assign_splits([dict(r) for r in rows])]
    s2 = [r["split"] for r in incidents.assign_splits([dict(r) for r in rows])]
    assert s1 == s2 and s1[0] == s1[1]
    assert 0.35 < s1.count("dev") / len(s1) < 0.85


def test_block_ranges_and_components():
    assert backtest.block_ranges([10, 12, 30], 1) == [(9, 13), (29, 31)]
    rows = [dict(seed_address=a(1), drainer=a(9), block=5), dict(seed_address=a(2), drainer=a(9), block=3),
            dict(seed_address=a(3), drainer="", block=1)]
    comps = backtest.components(rows)
    assert sorted(len(c) for c in comps) == [1, 2]
    assert [r["block"] for c in comps if len(c) == 2 for r in c] == [3, 5]


def test_spread_is_even_and_stable():
    assert incidents.spread(list(range(10)), 4) == [0, 3, 6, 9]
    assert incidents.spread([1, 2], 4) == [1, 2]


def test_load_env_file_never_overrides(tmp_path, monkeypatch):
    from drainerwatch.util import load_env_file
    p = tmp_path / "x.env"
    p.write_text("# c\nFOO_A=1\nexport FOO_B='2'\nFOO_C=3\n", encoding="utf-8")
    monkeypatch.setenv("FOO_C", "keep")
    monkeypatch.delenv("FOO_A", raising=False)
    monkeypatch.delenv("FOO_B", raising=False)
    assert load_env_file(p) == ["FOO_A", "FOO_B"]
    import os
    assert os.environ["FOO_C"] == "keep" and os.environ["FOO_B"] == "2"
    monkeypatch.delenv("FOO_A")
    monkeypatch.delenv("FOO_B")


def test_approval_helper_exists():
    assert approval_log(tx_hash(1), TOKEN, a(1), a(2))["topics"]
