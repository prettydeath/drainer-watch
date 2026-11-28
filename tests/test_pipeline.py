"""End-to-end on synthetic chunks: D2 -> payouts/drains -> rollup -> tier; VASP links (direct, deposit_sweep)."""
import json

from drainerwatch import enrich, rollup, scan
from drainerwatch.seeds import SeedSet
from tests.helpers import PULLER_CODE, FakeRpc, a, make_ctx, transfer_log, tx_hash, tx_info

TOKEN = a(0xAAA)
OP, AFF, DRAINER, ATTACKER = a(2), a(3), a(4), a(5)
CODE = "0x" + "60806040" * 40


def drain_chunk(victims, base_tx=1, block=100):
    logs, txs = [], {}
    for i, v in enumerate(victims):
        h = tx_hash(base_tx + i)
        logs += [transfer_log(h, TOKEN, v, OP, 2000, block=block, li=2 * i),
                 transfer_log(h, TOKEN, v, AFF, 8000, block=block, li=2 * i + 1)]
        txs[h] = tx_info(ATTACKER, DRAINER, block)
    return logs, txs


def test_split_pull_end_to_end_t1():
    victims = [a(0xABC000 + i) for i in range(3)]
    logs, txs = drain_chunk(victims)
    # policy.py: since the precision audit a split pull alone is a T3 signal (1 TP / 14 FP on the live site); T1 needs
    # drainer code (here a tiny owner-gated puller) with an observed pull. Opaque code stays at T3 (next test).
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: PULLER_CODE}, symbols={TOKEN: ("WXYZ", 18)}))
    scan.process_chunk(ctx, 100, 100, logs)
    c = ctx.conn
    assert c.execute("SELECT COUNT(*) FROM drains").fetchone()[0] == 6
    assert c.execute("SELECT COUNT(*) FROM evidence WHERE type='split_pull'").fetchone()[0] == 3
    roles = {r["wallet"]: r["role"] for r in c.execute("SELECT wallet,role FROM payouts")}
    assert roles == {AFF: "affiliate", OP: "operator"}
    rows = rollup.rollup(c, SeedSet(), {})
    assert [(r["address"], r["tier"], r["victims"]) for r in rows] == [(DRAINER, "T1", 3)]
    # re-processing the same chunk is idempotent
    scan.process_chunk(ctx, 100, 100, logs)
    assert c.execute("SELECT COUNT(*) FROM drains").fetchone()[0] == 6
    assert c.execute("SELECT txs FROM payouts WHERE wallet=?", (AFF,)).fetchone()[0] == 3


def test_split_pull_of_opaque_code_is_t3_signal_only():
    logs, txs = drain_chunk([a(0xABC000 + i) for i in range(3)])
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}, symbols={TOKEN: ("WXYZ", 18)}))
    scan.process_chunk(ctx, 100, 100, logs)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert (r["rule_tier"], r["tier"], r["code_class"]) == ("T1", "T3", "generic") and "weak_only_capped" in r["labels"]


def test_single_victim_is_t2_and_allowlisted_is_nothing():
    logs, txs = drain_chunk([a(0xABC000)])
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: PULLER_CODE}))   # drainer code: a one-victim split stays T2
    ctx.prices.usd = lambda chain, token, value, dec: 1000.0           # priced token
    scan.process_chunk(ctx, 100, 100, logs)
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T2"

    cow = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
    txs2 = {h: dict(t, to=cow) for h, t in txs.items()}
    ctx2 = make_ctx(FakeRpc(txs=txs2, codes={cow: CODE}))
    scan.process_chunk(ctx2, 100, 100, logs)
    assert rollup.rollup(ctx2.conn, SeedSet(), {}) == []


def test_victim_sent_tx_and_spoof_token_are_ignored():
    logs, txs = drain_chunk([a(0xABC000)])
    txs = {h: dict(t, **{"from": a(0xABC000)}) for h, t in txs.items()}      # victim == tx.from
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}))
    scan.process_chunk(ctx, 100, 100, logs)
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []
    logs, txs = drain_chunk([a(0xABC000)])
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}, symbols={TOKEN: ("U5DT", 6)}))
    scan.process_chunk(ctx, 100, 100, logs)
    r = rollup.rollup(ctx.conn, SeedSet(), {})
    assert [x["tier"] for x in r] == ["T3"] and ctx.conn.execute("SELECT COUNT(*) FROM drains").fetchone()[0] == 0


def test_seed_with_activity_is_t1_and_without_activity_absent():
    seeds = SeedSet([(a(0x777), None, "ss", "scamsniffer"), (a(0x778), None, "ss", "scamsniffer")])
    ctx = make_ctx(seeds=seeds)
    scan.process_chunk(ctx, 100, 100, [transfer_log(tx_hash(9), TOKEN, a(0xABC000), a(0x777), 5)])
    rows = rollup.rollup(ctx.conn, seeds, {})
    assert [(r["address"], r["tier"], r["source"]) for r in rows] == [(a(0x777), "T1", "scamsniffer")]


def test_vasp_direct_and_deposit_sweep_links():
    exch, dep = a(0xE0), a(0xD0)
    labels = {("eth", exch): ("Binance", "exchange", "Binance 14")}
    logs, txs = drain_chunk([a(0xABC000 + i) for i in range(3)])
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: PULLER_CODE}), labels=labels)   # T1 (drainer code + pulls)
    scan.process_chunk(ctx, 100, 100, logs)
    rollup.rollup(ctx.conn, SeedSet(), labels)
    # chunk 2: affiliate wallet pays a fresh address X and the drainer pays the exchange directly
    scan.refresh_known(ctx)
    scan.process_chunk(ctx, 101, 101, [transfer_log(tx_hash(50), TOKEN, AFF, dep, 777, block=101),
                                       transfer_log(tx_hash(51), TOKEN, DRAINER, exch, 5, block=101, li=1)])
    # chunk 3, a few hours later: X forwards to the exchange hot wallet
    scan.process_chunk(ctx, 102, 102, [transfer_log(tx_hash(52), TOKEN, dep, exch, 770, block=102)])
    links = {(r["kind"], r["subject"], r["counterparty"]): dict(r) for r in ctx.conn.execute("SELECT * FROM vasp_links")}
    assert ("direct", DRAINER, exch) in links
    sweep = links[("deposit_sweep", AFF, dep)]
    assert sweep["entity"] == "Binance" and sweep["confidence"] == "medium"
    assert sweep["tx"] == tx_hash(52) and sweep["tx_in"] == tx_hash(50)


def test_deposit_sweep_window():
    assert enrich.is_deposit_sweep(1000, 1000 + 72 * 3600, True)
    assert not enrich.is_deposit_sweep(1000, 1000 + 72 * 3600 + 1, True)
    assert not enrich.is_deposit_sweep(1000, 999, True)
    assert not enrich.is_deposit_sweep(1000, 2000, False)


def test_pick_funder_and_deployer_unknown_stays_null():
    dep = a(0xDD)
    normal = [dict(**{"from": a(1), "to": dep, "value": "5", "timeStamp": "200", "hash": "0xn", "isError": "0"}),
              dict(**{"from": a(9), "to": a(7), "value": "5", "timeStamp": "100", "hash": "0xx", "isError": "0"})]
    internal = [dict(**{"from": a(2), "to": dep, "value": "7", "timeStamp": "150", "transactionHash": "0xi"})]
    assert enrich.pick_funder(dep, normal, internal) == (a(2), "0xi", 150)
    assert enrich.pick_funder(dep, [], []) is None

    ctx = make_ctx()
    ctx.conn.execute("INSERT INTO contracts(chain,address,tier,score,last_seen) VALUES('eth',?, 'T1', 80, '2026-01-01T00:00:00Z')", (DRAINER,))

    class NoEtherscan:
        enabled = False
        unsupported = set()

        def call(self, *a, **k):
            return None

    enrich.resolve_deployers(ctx.conn, NoEtherscan(), {}, {})
    row = ctx.conn.execute("SELECT * FROM contract_deployer").fetchone()
    assert row["deployer"] is None and row["via"] == "unknown"        # never guessed


def test_toplevel_creation_is_the_deployer():
    ctx = make_ctx()
    ctx.conn.execute("INSERT INTO contracts(chain,address,tier,score,last_seen) VALUES('eth',?, 'T2', 50, '2026-01-01T00:00:00Z')", (DRAINER,))
    ctx.conn.execute("INSERT INTO creations VALUES('eth',?,?,?,1,1)", (DRAINER, ATTACKER, tx_hash(5)))

    class Es:
        enabled = True
        unsupported = set()

        def call(self, chain, params):
            if params["action"] == "txlist":
                return [{"from": a(0xF0), "to": ATTACKER, "value": "9", "timeStamp": "10", "hash": "0xfund", "isError": "0"}]
            return []

    labels = {("eth", a(0xF0)): ("FixedFloat", "exchange", "FixedFloat")}
    ctx.conn.execute("INSERT INTO labels VALUES('eth',?,'FixedFloat','FixedFloat','exchange')", (a(0xF0),))
    enrich.resolve_deployers(ctx.conn, Es(), {}, labels)
    d = ctx.conn.execute("SELECT * FROM contract_deployer").fetchone()
    assert (d["deployer"], d["via"], d["tx"]) == (ATTACKER, "toplevel", tx_hash(5))
    link = ctx.conn.execute("SELECT * FROM vasp_links").fetchone()
    assert (link["kind"], link["entity"], link["subject_role"]) == ("funding", "FixedFloat", "deployer")
    from drainerwatch.render import build_payload
    p = build_payload(ctx.conn)
    c = p["contracts"][0]
    assert c["deployer"]["funder"] == a(0xF0) and c["deployer"]["funder_entity"] == "FixedFloat"
    assert p["vasps"][0]["entity"] == "FixedFloat" and json.dumps(p)
