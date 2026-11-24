"""Per-chain shard databases: one-time migration from a full copy, merge (replace scan state per chain, union shared)."""
import shutil

from drainerwatch import shards
from drainerwatch.db import add_evidence, connect, meta_get, meta_set


def _full(path):
    c = connect(path)
    for ch in ("eth", "bsc"):
        add_evidence(c, ch, "0x" + "1" * 40, "split_pull", "0x" + ch.encode().hex().ljust(64, "0"), 1, 1, {})
        meta_set(c, f"cursor:{ch}", 100)
        c.execute("INSERT INTO vasp_links(chain,subject,subject_role,counterparty,kind,tx) VALUES(?,?,?,?,?,?)",
                  (ch, "0xs", "drainer", "0xc", "direct", "0xt" + ch))
    meta_set(c, "seeds_ss_at", 5)
    c.commit()
    return c


def test_init_shard_keeps_only_its_chain(tmp_path):
    full = tmp_path / "full.sqlite"
    _full(full).close()
    sp = tmp_path / "drainerwatch-bsc.sqlite"
    shutil.copy(full, sp)
    c = connect(sp)
    assert shards.init_shard(c, "bsc") and not shards.init_shard(c, "bsc")
    assert {r[0] for r in c.execute("SELECT DISTINCT chain FROM evidence")} == {"bsc"}
    assert meta_get(c, "cursor:eth") is None and meta_get(c, "cursor:bsc") == "100" and meta_get(c, "seeds_ss_at") == "5"


def test_merge_replaces_scan_state_per_chain(tmp_path):
    main = _full(tmp_path / "main.sqlite")
    sp = tmp_path / "drainerwatch-bsc.sqlite"
    s = connect(sp)
    shards.init_shard(s, "bsc")
    add_evidence(s, "bsc", "0x" + "2" * 40, "split_xtx", "0x" + "ab" * 32, 2, 2, {})
    meta_set(s, "cursor:bsc", 555)
    s.execute("INSERT INTO vasp_links(chain,subject,subject_role,counterparty,kind,tx) VALUES('bsc','0xs2','drainer','0xc','direct','0xt2')")
    s.commit()
    s.close()
    res = shards.merge(main, [sp, tmp_path / "missing.sqlite"])
    assert "bsc" in res
    ev = {(r["chain"], r["type"]) for r in main.execute("SELECT chain,type FROM evidence")}
    assert ev == {("eth", "split_pull"), ("bsc", "split_xtx")}           # bsc replaced, eth untouched
    assert meta_get(main, "cursor:bsc") == "555" and meta_get(main, "cursor:eth") == "100"
    assert main.execute("SELECT COUNT(*) FROM vasp_links WHERE chain='bsc'").fetchone()[0] == 2   # union
