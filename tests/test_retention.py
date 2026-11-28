"""Bounded retention (drainerwatch/retention.py) and the reduced shard merge: T1/T2 roll-up never changes."""
import json

from drainerwatch import retention, rollup, shards
from drainerwatch.db import add_evidence, connect, meta_get, meta_set
from drainerwatch.seeds import SeedSet

from tests.helpers import a, tx_hash

NOW = 1_800_000_000
DAY = 86400


def _drain(c, chain, tx, li, ts, victim, drainer, usd=100.0):
    c.execute("INSERT INTO drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,recipient) "
              "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (chain, tx, li, ts, victim, drainer, a(9), "USDT", 6, "1", usd, a(8)))


def _synthetic(path):
    """T1 split drainer with many pulls, T2 D4 payer, T3 inferred payers (one with 400 weak D4 rows), an old T3 lead,
    an old untiered subject, a public router and a T1 spender with many approvers."""
    c = connect(path)
    n = [0]

    def tx():
        n[0] += 1
        return tx_hash(n[0])

    t1 = a(0x1001)
    for i in range(120):                                   # T1: D2 with >= 3 victims, 120 multi-victim pulls
        h = tx()
        add_evidence(c, "eth", t1, "split_pull", h, 1, NOW - i * 600, dict(victims=[a(0x5000 + i)], token=a(9),
                                                                         recipients=[dict(wallet=a(7), share=0.8)]))
        _drain(c, "eth", h, 0, NOW - i * 600, a(0x5000 + i), t1)
        add_evidence(c, "eth", t1, "multi_victim_pull", tx(), 1, NOW - i * 600, dict(victims=[a(0x6000 + i)]))
    # policy.py: split_pull alone is a T3 signal since the precision audit; T1 needs drainer code (an owner-gated
    # puller dispatcher) with an observed pull
    c.execute("INSERT INTO codes(chain,address,code_hash,size,skeleton,selectors) VALUES('eth',?,'0x1',900,'s','[]')", (t1,))
    add_evidence(c, "eth", t1, "bytecode", tx(), 1, NOW, dict(owner_gated_puller=True, size=900))
    t2 = a(0x1002)                                         # T2: strong D4 (pays a seed / T1 operator wallet), 300 rows
    for i in range(300):
        add_evidence(c, "eth", t2, "pays_known_operator", tx(), 1, NOW - i * 60, dict(wallet=a(7), token=a(9), strong=True))
    # pays_known_operator alone is a T3 signal since the precision audit (0 TP / 6 FP): T2 from a K9 owner collect
    add_evidence(c, "eth", t2, "owner_collect", tx(), 1, NOW, dict(victim=a(0x7001)))
    t3 = a(0x1003)                                         # T3: weak D4 only (pays_inferred_operator), 400 rows
    for i in range(400):
        add_evidence(c, "eth", t3, "pays_known_operator", tx(), 1, NOW - i * 60, dict(wallet=a(6), token=a(9), strong=False))
    old3 = a(0x1004)                                       # T3 lead, quiet for 20 days
    for i in range(3):
        add_evidence(c, "eth", old3, "pays_known_operator", tx(), 1, NOW - 20 * DAY - i, dict(wallet=a(6), strong=False))
    c.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'operator',0.1,3)", (old3, a(6)))
    old_u = a(0x1005)                                      # untiered (one weak D4 tx), quiet for 10 days
    add_evidence(c, "eth", old_u, "pays_known_operator", tx(), 1, NOW - 10 * DAY, dict(wallet=a(6), strong=False))
    router, t1sp = a(0x2001), a(0x1001)
    for i in range(1100):                                  # public router: 1100 approvers, 3 approvals each
        for k in range(3):
            c.execute("INSERT INTO approvals(chain,owner,spender,token,tx,block,ts) VALUES('eth',?,?,?,?,1,?)",
                      (a(0x10000 + i), router, a(9), tx(), NOW - k))
        c.execute("INSERT INTO approvals(chain,owner,spender,token,tx,block,ts) VALUES('eth',?,?,?,?,1,?)",
                  (a(0x10000 + i), t1sp, a(9), tx(), NOW))
    c.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'affiliate',0.8,120)", (t1, a(7)))
    c.commit()
    return c, dict(t1=t1, t2=t2, t3=t3, old3=old3, old_u=old_u, router=router)


def _roll(c):
    return {(r["chain"], r["address"]): r for r in rollup.rollup(c, SeedSet(), {}, now=NOW)}


def _key(r):
    return r["tier"], r["victims"], r["drains"], r["usd"], tuple(r["labels"]), r["first"], r["last"]


def test_retention_keeps_t1_t2_rollup_identical(tmp_path):
    c, s = _synthetic(tmp_path / "shard.sqlite")
    before = _roll(c)
    assert before[("eth", s["t1"])]["tier"] == "T1" and before[("eth", s["t2"])]["tier"] == "T2"
    assert before[("eth", s["t3"])]["tier"] == "T3"
    st = retention.run(c, "eth", protect=set(), now=NOW)
    assert st["public_spenders"] == 1 and st["subjects_expired"] == 2 and st["pko_pruned"] > 0
    after = _roll(c)
    for k, r in before.items():
        if r["tier"] in ("T1", "T2"):
            assert _key(after[k]) == _key(r), k                  # tier, victims, drains, usd, labels, first/last seen
        elif k in after:
            assert rollup.TIER_RANK[after[k]["tier"]] >= rollup.TIER_RANK[r["tier"]]   # never raised
    assert ("eth", s["old3"]) not in after and ("eth", s["old_u"]) not in after
    assert c.execute("SELECT COUNT(*) FROM payouts WHERE drainer=?", (s["old3"],)).fetchone()[0] == 0
    # T1 evidence untouched (protected by its own tier); weak D4 rows of the T3 bounded
    assert c.execute("SELECT COUNT(*) FROM evidence WHERE address=?", (s["t1"],)).fetchone()[0] == 241
    n3 = c.execute("SELECT COUNT(*) FROM evidence WHERE address=?", (s["t3"],)).fetchone()[0]
    assert n3 <= retention.PKO_FIRST + retention.PKO_LAST
    # approvals: router gone, the T1 spender (protected) kept, one row per (owner, spender)
    assert c.execute("SELECT COUNT(*) FROM approvals WHERE spender=?", (s["router"],)).fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM approvals WHERE spender=?", (s["t1"],)).fetchone()[0] == 1100
    assert s["router"] in json.loads(meta_get(c, "public_spenders:eth"))


def test_retention_without_protect_list_is_lossless_only(tmp_path):
    c, s = _synthetic(tmp_path / "shard.sqlite")
    before = _roll(c)
    st = retention.run(c, "eth", protect=None, now=NOW)
    assert "subjects_expired" not in st and "evidence_pruned" not in st
    after = _roll(c)
    assert {k: _key(r) for k, r in after.items()} == {k: _key(r) for k, r in before.items()}   # every tier unchanged


def test_protect_list_shields_subjects_tiered_only_in_main(tmp_path):
    c, s = _synthetic(tmp_path / "shard.sqlite")
    _roll(c)
    retention.run(c, "eth", protect={("eth", s["old3"])}, now=NOW)
    assert c.execute("SELECT COUNT(*) FROM evidence WHERE address=?", (s["old3"],)).fetchone()[0] == 3


def test_protect_file_roundtrip_and_staleness(tmp_path):
    c, s = _synthetic(tmp_path / "main.sqlite")
    _roll(c)
    p = tmp_path / "protect.json"
    assert retention.write_protect(c, p) == 2
    assert retention.load_protect(p) == {("eth", s["t1"]), ("eth", s["t2"])}
    d = json.loads(p.read_text())
    d["at"] -= 3 * DAY
    p.write_text(json.dumps(d))
    assert retention.load_protect(p) is None                         # stale: step 3 skipped
    p.write_text('{"message": "Not Found"}')
    assert retention.load_protect(p) is None                         # an API error body is not an empty list
    assert retention.load_protect(tmp_path / "missing.json") is None


def test_public_spender_not_stored_again(tmp_path):
    from tests.helpers import make_ctx
    from drainerwatch import scan
    ctx = make_ctx()
    meta_set(ctx.conn, "public_spenders:eth", json.dumps({a(0x2001): 10 ** 10}))
    scan.load_state(ctx)
    assert a(0x2001) in ctx.public_spenders
    aps = [dict(kind="approval", value=1, owner=a(0x10 + i), spender=a(0x2001), token=a(9), tx=tx_hash(i), block=1)
           for i in range(5)]
    scan.store_approvals(ctx, aps, NOW)
    assert ctx.conn.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0


def test_g_funds_capped_per_recipient(tmp_path):
    from drainerwatch import gscan
    c = connect(tmp_path / "s.sqlite")
    gscan.ensure_tables(c)
    c.executemany("INSERT INTO g_funds(chain,recipient,funder,value,nonce,tx,block,ts) VALUES('eth',?,?,'1',0,?,1,?)",
                  [(a(1), a(0x100 + i), tx_hash(i), NOW + i) for i in range(retention.G2_MAX_ROWS + 50)]
                  + [(a(2), a(0x100 + i), tx_hash(10 ** 6 + i), NOW) for i in range(5)])
    assert retention.cap_g_funds(c, "eth") == 50
    assert c.execute("SELECT MIN(ts) FROM g_funds WHERE recipient=?", (a(1),)).fetchone()[0] == NOW + 50   # newest kept
    assert c.execute("SELECT COUNT(*) FROM g_funds WHERE recipient=?", (a(2),)).fetchone()[0] == 5


def test_merge_keeps_shard_only_tables_out_and_upserts_caches(tmp_path):
    main = connect(tmp_path / "main.sqlite")
    main.execute("INSERT INTO approvals(chain,owner,spender,token,tx,block,ts) VALUES('eth','o','s','t','x',1,1)")
    main.execute("INSERT INTO flows(chain,subject,x,tx) VALUES('eth','s','x','t')")
    main.execute("INSERT INTO codes(chain,address,code_hash,size) VALUES('eth','0xmainonly','h',5)")     # exposure-resolved
    main.execute("INSERT INTO codes(chain,address,code_hash,size) VALUES('eth','0xboth','old',5)")
    main.commit()
    sp = tmp_path / "drainerwatch-eth.sqlite"
    s = connect(sp)
    shards.init_shard(s, "eth")
    s.execute("INSERT INTO approvals(chain,owner,spender,token,tx,block,ts) VALUES('eth','o2','s2','t','x2',1,1)")
    s.execute("INSERT INTO codes(chain,address,code_hash,size) VALUES('eth','0xboth','new',5)")
    add_evidence(s, "eth", a(1), "split_pull", tx_hash(1), 1, NOW, {})
    s.commit()
    s.close()
    shards.merge(main, [sp])
    assert main.execute("SELECT COUNT(*) FROM approvals").fetchone()[0] == 0
    assert main.execute("SELECT COUNT(*) FROM flows").fetchone()[0] == 0
    codes = {r[0]: r[1] for r in main.execute("SELECT address,code_hash FROM codes")}
    assert codes == {"0xmainonly": "h", "0xboth": "new"}                    # main-only cache kept, shard wins
    assert main.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 1
    # the tables still exist (empty) with their indexes
    assert main.execute("SELECT 1 FROM sqlite_master WHERE name='ix_appr_owner'").fetchone()


def test_flows_outside_the_sweep_window_and_over_cap_pruned(tmp_path):
    from drainerwatch.constants import SWEEP_WINDOW
    c = connect(tmp_path / "s.sqlite")
    rows = [("eth", a(1), "drainer", a(0x100 + i), tx_hash(i), 1, NOW - 60 * i) for i in range(retention.FLOWS_MAX_PER_SUBJECT + 10)]
    rows += [("eth", a(2), "payout", a(0x9000), tx_hash(10 ** 6), 1, NOW - SWEEP_WINDOW - 1),
             ("eth", a(2), "payout", a(0x9001), tx_hash(10 ** 6 + 1), 1, NOW - SWEEP_WINDOW + 60)]
    c.executemany("INSERT INTO flows(chain,subject,role,x,tx,block,ts) VALUES(?,?,?,?,?,?,?)", rows)
    assert retention.prune_flows(c, "eth", NOW) == 11
    assert c.execute("SELECT COUNT(*) FROM flows WHERE subject=?", (a(1),)).fetchone()[0] == retention.FLOWS_MAX_PER_SUBJECT
    assert [r[0] for r in c.execute("SELECT x FROM flows WHERE subject=?", (a(2),))] == [a(0x9001)]


def test_cli_imports_and_parses():
    import pytest
    from drainerwatch import cli
    with pytest.raises(SystemExit):
        cli.main(["--help"])
