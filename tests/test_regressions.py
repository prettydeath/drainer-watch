"""Regressions from the first live review: router self-payment, D4 cascades, legit-label guard, AMM pools, spoof tokens,
positive fixtures, keyless deployer block-search."""
from drainerwatch import detectors, enrich, rollup, scan
from drainerwatch.constants import STABLES
from drainerwatch.db import connect
from drainerwatch.rpc import parse_logs
from drainerwatch.seeds import SeedSet
from tests.helpers import FakeRpc, a, make_ctx, transfer_log, tx_hash, tx_info

TOKEN = a(0xAAA)
CODE = "0x" + "60806040" * 40
ATTACKER, DRAINER = a(5), a(4)
V = lambda i: a(0xABC000 + i)  # noqa: E731


def never(_):
    return False


def cand(logs):
    tr, _ = parse_logs(logs)
    return detectors.d2_candidates(tr, never)[0]


# ---- 1. router paying itself / labelled recipients ----
def test_d2_rejects_split_where_recipient_is_tx_to_or_tx_from_or_labelled():
    fee = a(0xFEE)
    c = cand([transfer_log(tx_hash(1), TOKEN, V(1), DRAINER, 68), transfer_log(tx_hash(1), TOKEN, V(1), fee, 32, li=1)])
    isc = lambda x: x == DRAINER  # noqa: E731
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": DRAINER}, isc, never) is None       # recipient == tx.to
    c = cand([transfer_log(tx_hash(1), TOKEN, V(1), ATTACKER, 68), transfer_log(tx_hash(1), TOKEN, V(1), fee, 32, li=1)])
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": DRAINER}, isc, never) is None       # recipient == tx.from
    c = cand([transfer_log(tx_hash(1), TOKEN, V(1), a(7), 68), transfer_log(tx_hash(1), TOKEN, V(1), fee, 32, li=1)])
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": DRAINER}, isc, never, lambda w: w == fee) is None  # labelled
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": DRAINER}, isc, never) is not None


def test_pipeline_router_self_payment_not_flagged_and_labelled_recipient_blocks():
    logs, txs = [], {}
    for i in range(3):
        h = tx_hash(i + 1)
        logs += [transfer_log(h, TOKEN, V(i), DRAINER, 680, li=2 * i), transfer_log(h, TOKEN, V(i), a(0xFEE), 320, li=2 * i + 1)]
        txs[h] = tx_info(ATTACKER, DRAINER)
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}))
    scan.process_chunk(ctx, 100, 100, logs)
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []


# ---- 2. D4 cascades and legit labels ----
def d4_setup(tier, code_for_wallet="0x"):
    seeds = SeedSet()
    wallet, x = a(0x51), a(0x52)
    ctx = make_ctx(FakeRpc(codes={x: CODE, wallet: code_for_wallet}), seeds=seeds)
    ctx.conn.execute("INSERT INTO contracts(chain,address,tier,score,last_seen) VALUES('eth',?,?,50,'2026-01-01T00:00:00Z')",
                     (DRAINER, tier))
    ctx.conn.execute("INSERT INTO payouts VALUES('eth',?,?,'operator',0.2,1)", (DRAINER, wallet))
    scan.refresh_known(ctx)
    for i in (1, 2):
        scan.process_chunk(ctx, 100 + i, 100 + i, [transfer_log(tx_hash(i), TOKEN, x, wallet, 5, block=100 + i)])
    return ctx, x


def test_d4_from_inferred_wallet_is_t3_at_most():
    ctx, x = d4_setup("T2")
    rows = rollup.rollup(ctx.conn, SeedSet(), {})
    assert [(r["address"], r["tier"], r["labels"]) for r in rows] == [(x, "T3", ["pays_inferred_operator"])]


def test_d4_from_t1_payout_eoa_is_t2_but_contract_wallet_is_not_strong():
    ctx, x = d4_setup("T1")
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T2"
    ctx, x = d4_setup("T1", code_for_wallet=CODE)        # payout wallet has code -> inferred only
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T3"


def test_d4_from_seed_is_t2():
    wallet, x = a(0x61), a(0x62)
    seeds = SeedSet([(wallet, None, "ss", "scamsniffer")])
    ctx = make_ctx(FakeRpc(codes={x: CODE}), seeds=seeds)
    scan.refresh_known(ctx)
    for i in (1, 2):
        scan.process_chunk(ctx, 100 + i, 100 + i, [transfer_log(tx_hash(i), TOKEN, x, wallet, 5, block=100 + i)])
    assert {r["address"]: r["tier"] for r in rollup.rollup(ctx.conn, seeds, {})}[x] == "T2"


def test_legit_labelled_subject_is_never_flagged_and_labelled_victim_or_target_is_allowed():
    labels = {("eth", a(0xB0)): ("Morpho", "defi", "Morpho Blue"), ("eth", a(0xB1)): ("Some Corp", "entity", "x"),
              ("eth", a(0xB2)): ("Scammer", "scam", "x")}
    ctx = make_ctx(labels=labels)
    assert ctx.is_allowed(a(0xB0)) and ctx.is_allowed(a(0xB1)) and not ctx.is_allowed(a(0xB2))
    # even with D4-like evidence a labelled legit subject produces no contract row
    for i in (1, 2, 3):
        ctx.conn.execute("INSERT INTO evidence(chain,address,type,tx,block,ts,detail) VALUES('eth',?,'pays_known_operator',?,1,1,?)",
                         (a(0xB0), tx_hash(i), '{"strong": true}'))
    assert rollup.rollup(ctx.conn, SeedSet(), labels) == []
    ctx.conn.execute("UPDATE evidence SET address=?", (a(0xB2),))
    assert rollup.rollup(ctx.conn, SeedSet(), labels)[0]["address"] == a(0xB2)   # malicious label does not exempt


def test_amm_pool_by_factory_or_selectors_is_never_flagged():
    pool = a(0xE0)
    ctx = make_ctx()
    for i in (1, 2, 3):
        ctx.conn.execute("INSERT INTO evidence(chain,address,type,tx,block,ts,detail) VALUES('eth',?,'pays_known_operator',?,1,1,?)",
                         (pool, tx_hash(i), '{"strong": true}'))
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T2"
    v3 = "0x1f98431c8ad98523631ae4a59f267346ea31f984"
    ctx.conn.execute("INSERT INTO contract_deployer(chain,address,deployer,via,factory,resolved_at) VALUES('eth',?,?,?,?,1)",
                     (pool, a(9), "etherscan", v3))
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []
    ctx.conn.execute("DELETE FROM contract_deployer")
    ctx.conn.execute("INSERT INTO codes VALUES('eth',?,'h',500,'s',?)", (pool, '["0dfe1681","d21220a7","022c0d9f"]'))
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []


# ---- 3. positive fixtures ----
def test_positive_three_way_split_and_usdt_70_30():
    # 466-byte contract pattern: 3-way split (80 / 12 / 8), several victims, attacker-sent tx
    logs, txs = [], {}
    for i in range(3):
        h = tx_hash(i + 1)
        logs += [transfer_log(h, TOKEN, V(i), a(0xA1), 800, li=3 * i), transfer_log(h, TOKEN, V(i), a(0xA2), 120, li=3 * i + 1),
                 transfer_log(h, TOKEN, V(i), a(0xA3), 80, li=3 * i + 2)]
        txs[h] = tx_info(ATTACKER, DRAINER)
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}))
    scan.process_chunk(ctx, 100, 100, logs)
    r = rollup.rollup(ctx.conn, SeedSet(), {})
    assert [(x["address"], x["tier"], x["victims"]) for x in r] == [(DRAINER, "T1", 3)]
    assert ctx.conn.execute("SELECT role FROM payouts WHERE wallet=?", (a(0xA1),)).fetchone()[0] == "affiliate"

    # BSC USDT (canonical address, priced) 70/30, one victim: T3 since 2026-11-24 (no source verification on BSC for us,
    # a kit-like share alone is not enough: unverified_split_capped); was T2
    usdt = sorted(STABLES["bsc"])[0]
    usdt = "0x55d398326f99059ff775485246999027b3197955"
    h = tx_hash(9)
    ctx = make_ctx(FakeRpc(txs={h: tx_info(ATTACKER, DRAINER)}, codes={DRAINER: CODE}, symbols={usdt: ("USDT", 18)}), chain="bsc")
    scan.process_chunk(ctx, 100, 100, [transfer_log(h, usdt, V(1), a(0xB1), 70 * 10 ** 18), transfer_log(h, usdt, V(1), a(0xB2), 30 * 10 ** 18, li=1)])
    r = rollup.rollup(ctx.conn, SeedSet(), {})
    assert [(x["chain"], x["tier"], x["usd"]) for x in r] == [("bsc", "T3", 100.0)]
    assert {"share_grid", "unverified_split_capped"} <= set(r[0]["labels"])


def test_spoof_token_split_is_t3_without_drains_or_payouts():
    spoof = "U⁯S⁯DΤ"
    logs, txs = [], {}
    for i in range(3):
        h = tx_hash(i + 1)
        logs += [transfer_log(h, TOKEN, V(i), a(0xA1), 845, li=2 * i), transfer_log(h, TOKEN, V(i), a(0xA2), 155, li=2 * i + 1)]
        txs[h] = tx_info(ATTACKER, DRAINER)
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}, symbols={TOKEN: (spoof, 6)}))
    scan.process_chunk(ctx, 100, 100, logs)
    r = rollup.rollup(ctx.conn, SeedSet(), {})
    assert [(x["address"], x["tier"], x["labels"], x["victims"]) for x in r] == [(DRAINER, "T3", ["spoof_split"], 0)]
    assert ctx.conn.execute("SELECT COUNT(*) FROM drains").fetchone()[0] == 0
    assert ctx.conn.execute("SELECT COUNT(*) FROM payouts").fetchone()[0] == 0


# ---- 4. keyless deployer block-search ----
class ArchiveRpc:
    def __init__(self, created_block, archive=True, receipts=None, head=10_000):
        self.created, self.archive, self.receipts, self.head, self.n = created_block, archive, receipts or [], head, 0

    def block_number(self):
        return self.head

    def call(self, method, params, retries=2):
        from drainerwatch.util import HttpError
        if method == "eth_getCode":
            b = int(params[1], 16)
            self.n += 1
            if not self.archive and b < self.head - 100:
                raise HttpError("RPC error: missing trie node")
            return "0x6080" if b >= self.created else "0x"
        if method == "eth_getBlockReceipts":
            return self.receipts
        raise AssertionError(method)


def test_find_creation_block_binary_search():
    r = ArchiveRpc(7321)
    assert enrich.find_creation_block(r, DRAINER) == 7321
    assert r.n < 30
    import pytest
    with pytest.raises(enrich.NoArchive):
        enrich.find_creation_block(ArchiveRpc(7321, archive=False), DRAINER)


def test_resolve_deployers_block_search_toplevel_internal_and_no_archive():
    def setup(n):
        conn = connect(":memory:")
        for i in range(n):
            conn.execute("INSERT INTO contracts(chain,address,tier,score,last_seen) VALUES('base',?, 'T2', 50, '2026-01-01T00:00:00Z')", (a(0x100 + i),))
        return conn

    class NoEs:
        enabled = False
        unsupported = set()

        def call(self, *x, **k):
            return None

    conn = setup(1)
    rc = [{"contractAddress": a(0x100), "transactionHash": tx_hash(3), "from": ATTACKER}]
    enrich.resolve_deployers(conn, NoEs(), {"base": ArchiveRpc(500, receipts=rc)}, {})
    d = conn.execute("SELECT * FROM contract_deployer").fetchone()
    assert (d["via"], d["deployer"], d["tx"], d["block"]) == ("block-search", ATTACKER, tx_hash(3), 500)

    conn = setup(1)                                        # internal creation: block only, nothing guessed
    enrich.resolve_deployers(conn, NoEs(), {"base": ArchiveRpc(500, receipts=[])}, {})
    d = conn.execute("SELECT * FROM contract_deployer").fetchone()
    assert (d["via"], d["deployer"], d["factory"], d["block"]) == ("block-search", None, None, 500)

    conn = setup(15)                                       # cap of 10 per chain per run
    rpc = ArchiveRpc(500)
    enrich.resolve_deployers(conn, NoEs(), {"base": rpc}, {})
    rows = conn.execute("SELECT via FROM contract_deployer").fetchall()
    assert sum(r["via"] == "block-search" for r in rows) == 10 and sum(r["via"] == "unknown" for r in rows) == 5

    conn = setup(3)                                        # no archive: give up cleanly after the first probe
    rpc = ArchiveRpc(500, archive=False)
    enrich.resolve_deployers(conn, NoEs(), {"base": rpc}, {})
    assert {r["via"] for r in conn.execute("SELECT via FROM contract_deployer")} == {"unknown"} and rpc.n == 1
