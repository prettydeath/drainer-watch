"""Per-chain database shards. Each chain is scanned by its own job into data/drainerwatch-<chain>.sqlite (scan state:
cursor, gaps, evidence, drains, payouts, approvals, codes, ...). A final job merges the shards into the main database
(data/drainerwatch.sqlite), which keeps the cross-chain and enrichment state (roll-up, deployers, Etherscan caches,
freezable balances, exposure, alerts), and renders the site from it.

Merge rules: scan-state tables are REPLACED per chain (rows of chain C come only from shard C); caches also written by
the finish step on the main database (codes, tokens) are UPSERTED (shard rows win, main-only rows stay, so the finish
step does not re-resolve them every run); tables also written by the enrichment step are UNIONED (INSERT OR IGNORE);
`meta` keys of the form name:<chain> are replaced; tron_contracts comes from the TRON shard. Tables only the scanner
reads (approvals, g_funds, flows, tron_fund: 3.8 of 4.5 GB in Nov 2026) stay in the shards and are not merged."""
import logging
import sqlite3
from pathlib import Path

from .db import connect, meta_get, meta_set

log = logging.getLogger("drainerwatch.shards")

# scan state: the shard is the only writer of these rows (per chain)
REPLACE_TABLES = ("evidence", "drains", "payouts", "creations")
# caches written by the shard and by the finish step (exposure / Tokens) on the main database: shard rows win
UPSERT_TABLES = ("tokens", "codes")
# also written by the enrichment step on the main database: keep both
UNION_TABLES = ("vasp_links", "contract_deployer")
# read only by the scanner: never merged, emptied in the main database
SHARD_ONLY_TABLES = ("approvals", "g_funds", "flows")
TRON_TABLES = ("tron_contracts",)
TRON_SHARD_ONLY = ("tron_fund",)
META_PREFIXES = ("cursor", "gaps", "head", "scan_at", "chunk", "keyless", "stats")


def shard_path(data_dir: Path, chain: str) -> Path:
    return data_dir / f"drainerwatch-{chain}.sqlite"


def _cols(conn, schema, table):
    return [r[1] for r in conn.execute(f"PRAGMA {schema}.table_info({table})")]


def _has(conn, schema, table):
    return bool(conn.execute(f"SELECT 1 FROM {schema}.sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())


def init_shard(conn, chain):
    """A shard started from a copy of the old single database keeps only its own chain (one-time migration)."""
    if meta_get(conn, "shard_chain") == chain:
        return False
    for t in REPLACE_TABLES + UPSERT_TABLES + UNION_TABLES + SHARD_ONLY_TABLES + ("contracts",):
        if _has(conn, "main", t) and "chain" in _cols(conn, "main", t):
            conn.execute(f"DELETE FROM {t} WHERE chain != ?", (chain,))
    if chain != "tron":
        for t in TRON_TABLES + TRON_SHARD_ONLY:
            if _has(conn, "main", t):
                conn.execute(f"DELETE FROM {t}")
    for r in conn.execute("SELECT k FROM meta").fetchall():
        k = r["k"]
        if ":" in k and k.split(":", 1)[0] in META_PREFIXES and k.split(":", 1)[1] != chain:
            conn.execute("DELETE FROM meta WHERE k=?", (k,))
    meta_set(conn, "shard_chain", chain)
    conn.commit()
    try:
        conn.execute("VACUUM")
    except sqlite3.OperationalError:
        pass
    return True


def drop_shard_only(conn):
    """Empty the scanner-only tables in the main database (DROP + recreate: instant even for millions of rows).
    Returns the tables emptied."""
    from .db import SCHEMA
    done = []
    for t in SHARD_ONLY_TABLES + TRON_SHARD_ONLY:
        if _has(conn, "main", t) and conn.execute(f"SELECT 1 FROM main.{t} LIMIT 1").fetchone():
            ddl = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()[0]
            idx = [r[0] for r in conn.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
                                              (t,))]
            conn.execute(f"DROP TABLE main.{t}")
            conn.execute(ddl)
            for q in idx:
                conn.execute(q)
            done.append(t)
    conn.executescript(SCHEMA)
    conn.commit()
    return done


def merge(conn, shard_paths):
    """Merge shard databases into `conn` (the main database). Returns {chain: rows copied}."""
    out = {}
    dropped = drop_shard_only(conn)
    if dropped:
        log.info("main database: emptied scanner-only tables %s", ", ".join(dropped))
    for p in shard_paths:
        p = Path(p)
        if not p.exists():
            log.warning("shard %s missing; that chain keeps its previous state", p)
            continue
        src = connect(p)            # make sure the shard has the current schema
        chain = meta_get(src, "shard_chain")
        src.close()
        if not chain:
            log.warning("shard %s has no shard_chain; skipped", p)
            continue
        conn.execute("ATTACH DATABASE ? AS s", (str(p),))
        n = 0
        try:
            for t in REPLACE_TABLES + UPSERT_TABLES + UNION_TABLES:
                if not _has(conn, "s", t):
                    continue
                if not _has(conn, "main", t):
                    ddl = conn.execute("SELECT sql FROM s.sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()[0]
                    conn.execute(ddl)
                cols = [c for c in _cols(conn, "s", t) if c in set(_cols(conn, "main", t)) and c != "id"]   # ids differ
                if "chain" not in cols:
                    continue
                cl = ",".join(cols)
                if t in REPLACE_TABLES:
                    conn.execute(f"DELETE FROM main.{t} WHERE chain=?", (chain,))
                    cur = conn.execute(f"INSERT OR REPLACE INTO main.{t}({cl}) SELECT {cl} FROM s.{t} WHERE chain=?", (chain,))
                elif t in UPSERT_TABLES:
                    cur = conn.execute(f"INSERT OR REPLACE INTO main.{t}({cl}) SELECT {cl} FROM s.{t} WHERE chain=?", (chain,))
                else:
                    cur = conn.execute(f"INSERT OR IGNORE INTO main.{t}({cl}) SELECT {cl} FROM s.{t} WHERE chain=?", (chain,))
                n += max(0, cur.rowcount)
            if chain == "tron":
                for t in TRON_TABLES:
                    if _has(conn, "s", t):
                        cols = ",".join(c for c in _cols(conn, "s", t) if c in set(_cols(conn, "main", t)))
                        conn.execute(f"DELETE FROM main.{t}")
                        n += max(0, conn.execute(f"INSERT INTO main.{t}({cols}) SELECT {cols} FROM s.{t}").rowcount)
            for pre in META_PREFIXES:
                conn.execute("DELETE FROM main.meta WHERE k=?", (f"{pre}:{chain}",))
                conn.execute("INSERT OR REPLACE INTO main.meta(k,v) SELECT k,v FROM s.meta WHERE k=?", (f"{pre}:{chain}",))
            conn.commit()
        finally:
            conn.execute("DETACH DATABASE s")
        out[chain] = n
        log.info("merged shard %s (%s): %d rows", p.name, chain, n)
    from .retention import maybe_vacuum
    if maybe_vacuum(conn):
        log.info("main database vacuumed")
    return out
