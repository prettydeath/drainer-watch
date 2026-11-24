"""False-positive guards: redemption shape (mint/burn in the tx), 2-3 recipients, allowlist purge, verified-source cap."""
import json

from drainerwatch import detectors, enrich, rollup, scan
from drainerwatch.constants import ZERO
from drainerwatch.rpc import parse_logs
from drainerwatch.seeds import SeedSet
from tests.helpers import FakeRpc, a, make_ctx, transfer_log, tx_hash, tx_info

USDC, SHARE = a(0xAAA), a(0xBBB)
RESERVE, VAULT, CALLER = a(0xAB0011), a(0x22), a(0x33)
CODE = "0x" + "60806040" * 40
R = [a(0x51), a(0x52), a(0x53), a(0x54)]


def never(_):
    return False


def redemption_logs(h, n_recipients, burner, block=100):
    """reserve pays USDC to n recipients (largest first), `burner` burns its share token once per recipient"""
    amounts = [7000 * 10**6] + [1000 * 10**6] * (n_recipients - 1)
    logs = [transfer_log(h, USDC, RESERVE, R[i], amounts[i], block=block, li=i) for i in range(n_recipients)]
    logs += [transfer_log(h, SHARE, burner, ZERO, 10, block=block, li=10 + i) for i in range(n_recipients)]
    return logs


def run_chunk(logs, txs):
    ctx = make_ctx(FakeRpc(txs=txs, codes={VAULT: CODE}, symbols={USDC: ("WXYZ", 6)}),
                   native={"ETH": 2000.0})
    ctx.prices.usd = lambda chain, token, value, dec: value / 10 ** dec if token == USDC else None   # USDC priced 1.0
    scan.process_chunk(ctx, 100, 100, logs)
    return ctx


def test_d2_redemption_burn_by_tx_to_is_not_a_split():
    h = tx_hash(1)
    tx = {h: tx_info(CALLER, VAULT)}
    split = [transfer_log(h, USDC, RESERVE, R[0], 7000), transfer_log(h, USDC, RESERVE, R[1], 1500, li=1),
             transfer_log(h, USDC, RESERVE, R[2], 1500, li=2)]
    tr, _ = parse_logs(split)
    cand = detectors.d2_candidates(tr, never)[0]
    ok = detectors.d2_confirm(cand, tx[h], lambda x: x == VAULT, never)
    assert ok and ok["drainer"] == VAULT                                    # without a burn it is a split
    burn = parse_logs([transfer_log(h, SHARE, VAULT, ZERO, 5, li=9)])[0]    # the contract burns its own shares
    assert detectors.d2_confirm(cand, tx[h], lambda x: x == VAULT, never, mintburn=burn) is None
    token_is_to = parse_logs([transfer_log(h, VAULT, a(0x77), ZERO, 5, li=9)])[0]   # tx.to is the burnt token itself
    assert detectors.d2_confirm(cand, tx[h], lambda x: x == VAULT, never, mintburn=token_is_to) is None
    mint = parse_logs([transfer_log(h, SHARE, ZERO, VAULT, 5, li=9)])[0]    # a mint to tx.to alone is not a redemption
    assert detectors.d2_confirm(cand, tx[h], lambda x: x == VAULT, never, mintburn=mint)


def test_d2_needs_two_or_three_recipients():
    h = tx_hash(1)
    for n, expect in ((2, True), (3, True), (4, False)):
        tr, _ = parse_logs(redemption_logs(h, n, a(0x99))[:n])
        c = detectors.d2_candidates(tr, never)
        assert len(c) == 1
        got = detectors.d2_confirm(c[0], tx_info(CALLER, VAULT), lambda x: x == VAULT, never)
        assert bool(got) == expect, n


def test_redemption_like_pairs_burns_with_recipients():
    burns = lambda n: parse_logs([transfer_log(tx_hash(1), SHARE, R[i], ZERO, 1, li=i) for i in range(n)])[0]
    assert detectors.redemption_like(burns(4), VAULT, R)                    # 4 payees, 4 burns (burners are the payees)
    assert not detectors.redemption_like(burns(3), VAULT, R)                # a burn missing
    assert not detectors.redemption_like(burns(4), VAULT, R[:3])            # 3 recipients: not by this rule
    assert not detectors.redemption_like([], VAULT, R)


def test_d2_end_to_end_vault_batch_is_nothing():
    h = tx_hash(1)
    ctx = run_chunk(redemption_logs(h, 4, VAULT), {h: tx_info(CALLER, VAULT)})
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []
    h2 = tx_hash(2)
    ctx = run_chunk(redemption_logs(h2, 3, VAULT)[:3], {h2: tx_info(CALLER, VAULT)})        # same split, no burn
    assert [r["tier"] for r in rollup.rollup(ctx.conn, SeedSet(), {})] == ["T2"]
    ctx = run_chunk(redemption_logs(h2, 3, VAULT), {h2: tx_info(CALLER, VAULT)})            # with the burn
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []


def xtx_transfers(burn_in_second=False):
    h1, h2 = tx_hash(1), tx_hash(2)
    logs = [transfer_log(h1, USDC, RESERVE, R[0], 9000, block=100, li=0),
            transfer_log(h2, USDC, RESERVE, R[1], 1000, block=100, li=1)]
    if burn_in_second:
        logs.append(transfer_log(h2, SHARE, VAULT, ZERO, 5, block=100, li=2))
    tr, _ = parse_logs(logs)
    txs = {h1: tx_info(CALLER, VAULT), h2: tx_info(CALLER, VAULT)}
    return tr, txs


def test_split_xtx_redemption_guard():
    tr, txs = xtx_transfers()
    assert detectors.xsplit_groups(tr, txs, never, detectors.mint_burn_by_tx(tr))
    tr, txs = xtx_transfers(burn_in_second=True)
    assert detectors.xsplit_groups(tr, txs, never)                                          # no guard: would be a group
    assert detectors.xsplit_groups(tr, txs, never, detectors.mint_burn_by_tx(tr)) == {}


# ---------- allowlist purge ----------
def seed_split_evidence(ctx, addr, tx_n=1):
    h = tx_hash(tx_n)
    ctx.conn.execute("INSERT INTO evidence(chain,address,type,tx,block,ts,detail) VALUES('eth',?,?,?,1,?,?)",
                     (addr, "split_pull", h, 1_800_000_000, json.dumps(dict(victims=[a(0xA1)], token=USDC, recipients=[]))))
    ctx.conn.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'operator',0.1,1)",
                     (addr, R[0]))
    ctx.conn.execute("INSERT INTO drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,recipient) "
                     "VALUES('eth',?,0,1,?,?,?,?,6,'1',500,?)", (h, a(0xA1), addr, USDC, "USDC", R[0]))
    ctx.conn.commit()


def test_rollup_drops_allowlisted_subjects_and_purges_their_rows(monkeypatch):
    ctx = make_ctx()
    tangem = "0xf67e35af6a18a01702e6c2f1e18a63c2fc3a528c"           # built-in ALLOWLIST
    csv_only = a(0xC5F)                                             # data/allowlist.csv only
    monkeypatch.setattr(rollup, "load_allowlist", lambda chain: {csv_only} if chain == "eth" else set())
    for i, addr in enumerate((tangem, csv_only, VAULT)):
        seed_split_evidence(ctx, addr, i + 1)
    rows = rollup.rollup(ctx.conn, SeedSet(), {})
    assert [r["address"] for r in rows] == [VAULT]
    left = {r[0] for r in ctx.conn.execute("SELECT DISTINCT address FROM evidence")}
    assert left == {VAULT}
    assert {r[0] for r in ctx.conn.execute("SELECT drainer FROM drains")} == {VAULT}
    assert {r[0] for r in ctx.conn.execute("SELECT drainer FROM payouts")} == {VAULT}


def test_labelled_legit_subject_is_dropped_and_legit_payout_wallet_does_not_cluster():
    ctx = make_ctx()
    seed_split_evidence(ctx, VAULT, 1)
    other = a(0x23)
    seed_split_evidence(ctx, other, 2)
    assert {r["address"]: r.get("cluster") for r in rollup.rollup(ctx.conn, SeedSet(), {})}[VAULT] is not None   # shared wallet R[0]
    labels = {("eth", R[0]): ("Some Exchange", "exchange", "hot wallet")}
    rows = {r["address"]: r for r in rollup.rollup(ctx.conn, SeedSet(), labels)}
    assert rows[VAULT].get("cluster") is None
    labels = {("eth", VAULT): ("Protocol", "defi", "router")}
    assert [r["address"] for r in rollup.rollup(ctx.conn, SeedSet(), labels)] == [other]


# ---------- verified-source cap ----------
def cache_verified(conn, addr, verified=1, name="CombineCalls", proxy=0, impl=None, impl_verified=None, impl_name=None):
    conn.execute("INSERT OR REPLACE INTO verified_cache VALUES('eth',?,?,?,?,?,?,?,0)",
                 (addr, verified, name, proxy, impl, impl_verified, impl_name))
    conn.commit()


def flagged_ctx(addr=VAULT, extra_evidence=None):
    ctx = make_ctx()
    seed_split_evidence(ctx, addr)
    for typ, detail in (extra_evidence or []):
        ctx.conn.execute("INSERT INTO evidence(chain,address,type,tx,block,ts,detail) VALUES('eth',?,?,?,1,?,?)",
                         (addr, typ, tx_hash(99), 1_800_000_000, json.dumps(detail)))
    ctx.conn.commit()
    return ctx


def test_verified_contract_with_split_only_is_capped_at_t3():
    ctx = flagged_ctx()
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T2" and r["verified"] is None and r["contract_name"] is None
    cache_verified(ctx.conn, VAULT)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T3" and "verified_capped" in r["labels"] and r["contract_name"] == "CombineCalls"
    row = ctx.conn.execute("SELECT tier,verified,contract_name FROM contracts").fetchone()
    assert tuple(row) == ("T3", 1, "CombineCalls")
    cache_verified(ctx.conn, VAULT, verified=0, name=None)                  # unverified: unchanged
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T2"


def test_verified_cap_with_other_evidence_and_proxy_rules():
    ctx = flagged_ctx(extra_evidence=[("approval_fingerprint", dict(victim=a(0xA2), token=USDC, kit="x"))])
    cache_verified(ctx.conn, VAULT)
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T1"        # kit evidence still raises
    ctx = flagged_ctx()
    impl = a(0x84)
    cache_verified(ctx.conn, VAULT, name="TransparentUpgradeableProxy", proxy=1, impl=impl, impl_verified=1, impl_name="Vault")
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T3" and r["contract_name"] == "TransparentUpgradeableProxy (proxy of Vault)"
    cache_verified(ctx.conn, VAULT, name="TransparentUpgradeableProxy", proxy=1, impl=impl, impl_verified=0)
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T2"        # unverified implementation: no cap
    cache_verified(ctx.conn, VAULT, name="Proxy", proxy=1, impl=impl, impl_verified=None)
    assert rollup.rollup(ctx.conn, SeedSet(), {})[0]["tier"] == "T2"        # implementation unknown: no cap


class FakeEs:
    enabled = True

    def __init__(self, table):
        self.table, self.asked = table, []

    def call(self, chain, params):
        self.asked.append(params["address"])
        return self.table.get(params["address"])


def src(name, proxy=False, impl=""):
    return [dict(SourceCode="contract X {}", ABI="[]", ContractName=name, Proxy="1" if proxy else "0", Implementation=impl)]


UNVERIFIED = [dict(SourceCode="", ABI="Contract source code not verified", ContractName="", Proxy="0", Implementation="")]


def cand(addr, tier="T2", score=50, chain="eth", is_contract=1):
    return dict(chain=chain, address=addr, tier=tier, score=score, is_contract=is_contract)


def test_lookup_verified_caches_resolves_proxy_and_respects_cap():
    conn = make_ctx().conn
    impl, p, u = a(0x84), a(0x31), a(0x32)
    es = FakeEs({VAULT: src("CombineCalls"), p: src("TransparentUpgradeableProxy", True, impl), impl: src("Vault"),
                 u: UNVERIFIED})
    rows = [cand(VAULT), cand(p), cand(u), cand(a(0x40), tier="T3"), cand(a(0x41), chain="base"), cand(a(0x42), is_contract=0)]
    assert enrich.lookup_verified(conn, es, rows) == 4                       # 3 candidates + the proxy implementation
    assert sorted(es.asked) == sorted([VAULT, p, impl, u])
    got = {r["address"]: r for r in conn.execute("SELECT * FROM verified_cache")}
    assert got[VAULT]["verified"] == 1 and got[VAULT]["name"] == "CombineCalls"
    assert got[p]["proxy"] == 1 and got[p]["impl_verified"] == 1 and got[p]["impl_name"] == "Vault"
    assert got[u]["verified"] == 0
    es.asked.clear()
    assert enrich.lookup_verified(conn, es, rows) == 0 and es.asked == []   # all fresh: nothing to ask
    cap_es = FakeEs({})
    many = [cand(a(0x100 + i), score=i) for i in range(50)]
    assert enrich.lookup_verified(make_ctx().conn, cap_es, many, cap=30) == 30
    assert len(cap_es.asked) == 30 and cap_es.asked[0] == a(0x100 + 49)      # best score first
    assert enrich.lookup_verified(conn, type("E", (), {"enabled": False})(), [cand(a(0x200))]) == 0


# ---------- unpriced single-victim split cap ----------
def test_unpriced_single_victim_split_is_capped_at_t3():
    from tests.test_pipeline import DRAINER, drain_chunk
    from tests.test_kits_k import MS_NEW_CODE
    logs, txs = drain_chunk([a(0xABC000)])                    # unpriced token, one victim, 80/20 split
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}))
    scan.process_chunk(ctx, 100, 100, logs)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T3" and "unpriced_capped" in r["labels"]
    logs, txs = drain_chunk([a(0xABC000 + i) for i in range(2)])   # two victims: not capped
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: CODE}))
    scan.process_chunk(ctx, 100, 100, logs)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T2" and "unpriced_capped" not in r["labels"]
    logs, txs = drain_chunk([a(0xABC000)])                    # kit code (other evidence): not capped
    ctx = make_ctx(FakeRpc(txs=txs, codes={DRAINER: MS_NEW_CODE}))
    scan.process_chunk(ctx, 100, 100, logs)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T2" and "kit_signature" in r["labels"] and "unpriced_capped" not in r["labels"]
