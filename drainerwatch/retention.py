"""Bounded retention for the scan state (runs on each chain shard at the end of a scan; the merge copies the result).

What fills the database (run 46131694981, 4.5 GB main db): approvals 3.3 GB (5.4 M rows, 92 % of them for 114 public
routers / aggregators with > 300 approvers each, ~126 rows per owner for the largest), evidence 530 MB
(pays_known_operator 550 k rows: DEX routers paying fee wallets, one row per transfer), g_funds 254 MB (one CEX wallet
with 336 k funders), flows 251 MB. Rules, in order of safety:

1. Lossless for every tier:
   * approvals: one row per (owner, spender), the latest. D3 only needs the owner -> spender relation and the 7-day
     expiry keys on the newest approval.
   * pays_known_operator: per subject and strong/weak flag the earliest and latest rows only. The roll-up needs >= 2
     distinct txs per flag (D4_MIN_TXS), first/last seen and the newest MAX_EVIDENCE rows for the site.
   * flows: rows older than the 72 h sweep window (lossless); at most FLOWS_MAX_PER_SUBJECT per subject.
   * g_funds: the newest G2_MAX_ROWS rows per recipient. A recipient with that many funders inside the window is an
     exchange / service sink; G2 (funders_hit) looks at the newest row per funder anyway.
2. Public spenders: a spender with > PUBLIC_SPENDER_OWNERS distinct approvers inside the approval window that is not
   protected (T1/T2, seed, vanity) is a public router: its approvals are dropped and no longer stored. D3 candidates
   from their approvers were also the main source of per-tx RPC lookups on BSC.
3. Unprotected subjects only (not T1/T2 on this shard, not T1/T2 in the main database = data/protect.json, not seeds):
   * per (subject, evidence type) the earliest KEEP_FIRST and latest KEEP_LAST rows;
   * a T3 subject with no evidence for T3_TTL_SEC, or an untiered one for UNTIERED_TTL_SEC, is dropped entirely
     (evidence, drains, payouts).
   Without data/protect.json step 3 is skipped (a subject lifted to T1/T2 only by the merged roll-up must keep all
   of its evidence). Fewer rows can only lower a subject's labels / victim count, never raise its tier, and T1/T2
   rows are never touched by step 3."""
import json
import logging
import sqlite3
from pathlib import Path

from .constants import APPROVAL_KEEP_SEC, DATA_DIR
from .util import now_ts

log = logging.getLogger("drainerwatch.retention")

KEEP_FIRST, KEEP_LAST = 5, 20                # MAX_EVIDENCE (render) = 20 newest rows per subject on the site
PKO_FIRST, PKO_LAST = 2, 20
G2_MAX_ROWS = 500
PUBLIC_SPENDER_OWNERS = 300
FLOWS_MAX_PER_SUBJECT = 2000
T3_TTL_SEC = 14 * 86400
UNTIERED_TTL_SEC = 7 * 86400
PROTECT_FILE = DATA_DIR / "protect.json"
VACUUM_FREE_SHARE = 0.25


PROTECT_MAX_AGE_SEC = 2 * 86400


def load_protect(path=None, now=None):
    """Set of (chain, address) that are T1/T2 in the main database, or None if the file is missing, unreadable,
    malformed or older than PROTECT_MAX_AGE_SEC (step 3 is then skipped)."""
    p = Path(path or PROTECT_FILE)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "subjects" not in data or (now or now_ts()) - int(data["at"]) > PROTECT_MAX_AGE_SEC:
            return None
        return {(x["chain"], x["address"]) for x in data["subjects"]}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def write_protect(conn, path=None):
    """data/protect.json: T1/T2 subjects of the merged roll-up (read back by the scan jobs for step 3)."""
    rows = conn.execute("SELECT chain,address,tier FROM contracts WHERE tier IN ('T1','T2') ORDER BY chain,address").fetchall()
    p = Path(path or PROTECT_FILE)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(dict(at=now_ts(), subjects=[dict(chain=r[0], address=r[1], tier=r[2]) for r in rows]),
                            separators=(",", ":")), encoding="utf-8")
    return len(rows)


def _has(conn, table):
    return bool(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone())


def local_protected(conn, chain, seeds=None):
    """T1/T2 of this database's own roll-up plus seeds."""
    out = {(chain, r[0]) for r in conn.execute("SELECT address FROM contracts WHERE chain=? AND tier IN ('T1','T2')",
                                               (chain,))}
    if seeds is not None:
        out |= {(chain, a) for a in seeds.addresses(chain)}
    return out


def dedupe_approvals(conn, chain):
    """One approval row per (owner, spender): the newest (lossless for D3)."""
    return max(0, conn.execute(
        "DELETE FROM approvals WHERE chain=? AND rowid NOT IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER ("
        "PARTITION BY owner, spender ORDER BY ts DESC, rowid DESC) rn FROM approvals WHERE chain=?) WHERE rn = 1)",
        (chain, chain)).rowcount)


def public_spenders(conn, chain, keep, now=None, cap=PUBLIC_SPENDER_OWNERS):
    """Spenders with > cap distinct approvers that are not in `keep`: their approvals are deleted; the set (with the
    time each was found) is kept in meta public_spenders:<chain> for APPROVAL_KEEP_SEC. Returns the current set."""
    from .db import meta_get, meta_set
    from .wrules import is_vanity
    now = now or now_ts()
    try:
        known = {a: int(t) for a, t in json.loads(meta_get(conn, f"public_spenders:{chain}", "{}") or "{}").items()}
    except (ValueError, TypeError, AttributeError):
        known = {}
    known = {a: t for a, t in known.items() if now - t < APPROVAL_KEEP_SEC and (chain, a) not in keep}
    for r in conn.execute("SELECT spender, COUNT(DISTINCT owner) o FROM approvals WHERE chain=? GROUP BY spender "
                          "HAVING o > ?", (chain, cap)):
        a = r[0]
        if (chain, a) not in keep and not is_vanity(a):
            known.setdefault(a, now)
    if known:
        conn.executemany("DELETE FROM approvals WHERE chain=? AND spender=?", [(chain, a) for a in known])
    meta_set(conn, f"public_spenders:{chain}", json.dumps(known, sort_keys=True))
    return set(known)


def compact_pko(conn, chain):
    """pays_known_operator: earliest PKO_FIRST + latest PKO_LAST rows per (subject, strong flag)."""
    return max(0, conn.execute(
        "DELETE FROM evidence WHERE id IN (SELECT id FROM (SELECT id, "
        "ROW_NUMBER() OVER (PARTITION BY address, json_extract(detail,'$.strong') ORDER BY ts, id) a, "
        "ROW_NUMBER() OVER (PARTITION BY address, json_extract(detail,'$.strong') ORDER BY ts DESC, id DESC) d "
        "FROM evidence WHERE chain=? AND type='pays_known_operator') WHERE a > ? AND d > ?)",
        (chain, PKO_FIRST, PKO_LAST)).rowcount)


def cap_g_funds(conn, chain):
    if not _has(conn, "g_funds"):
        return 0
    return max(0, conn.execute(
        "DELETE FROM g_funds WHERE chain=? AND rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER ("
        "PARTITION BY recipient ORDER BY ts DESC, rowid DESC) rn FROM g_funds WHERE chain=?) WHERE rn > ?)",
        (chain, chain, G2_MAX_ROWS)).rowcount)


def prune_flows(conn, chain, now=None):
    """flows (subject -> X, awaiting a forward to an exchange): rows older than SWEEP_WINDOW can never match a sweep
    (lossless), and at most FLOWS_MAX_PER_SUBJECT newest rows per subject (a subject paying more distinct addresses
    than that inside 72 h is a service). The table is re-read by every scanned chunk, so its size is scan time."""
    from .constants import SWEEP_WINDOW
    now = now or now_ts()
    n = max(0, conn.execute("DELETE FROM flows WHERE chain=? AND ts IS NOT NULL AND ts < ?",
                            (chain, now - SWEEP_WINDOW)).rowcount)
    n += max(0, conn.execute(
        "DELETE FROM flows WHERE chain=? AND rowid IN (SELECT rowid FROM (SELECT rowid, ROW_NUMBER() OVER ("
        "PARTITION BY subject ORDER BY ts DESC, rowid DESC) rn FROM flows WHERE chain=?) WHERE rn > ?)",
        (chain, chain, FLOWS_MAX_PER_SUBJECT)).rowcount)
    return n


def _protected_temp(conn, keys):
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS _protect(chain TEXT, address TEXT, PRIMARY KEY (chain, address))")
    conn.execute("DELETE FROM _protect")
    conn.executemany("INSERT OR IGNORE INTO _protect VALUES(?,?)", sorted(keys))


def compact_unprotected(conn, chain, protect):
    """Per (subject, type) of unprotected subjects: earliest KEEP_FIRST + latest KEEP_LAST rows."""
    _protected_temp(conn, protect)
    return max(0, conn.execute(
        "DELETE FROM evidence WHERE id IN (SELECT id FROM (SELECT id, address, "
        "ROW_NUMBER() OVER (PARTITION BY address, type ORDER BY ts, id) a, "
        "ROW_NUMBER() OVER (PARTITION BY address, type ORDER BY ts DESC, id DESC) d "
        "FROM evidence WHERE chain=?) e WHERE a > ? AND d > ? "
        "AND NOT EXISTS (SELECT 1 FROM _protect p WHERE p.chain=? AND p.address=e.address))",
        (chain, KEEP_FIRST, KEEP_LAST, chain)).rowcount)


def expire_subjects(conn, chain, protect, now=None):
    """Drop unprotected subjects whose newest evidence is older than the TTL (T3: T3_TTL_SEC, untiered:
    UNTIERED_TTL_SEC), with their drains and payouts. Returns the number of subjects dropped."""
    now = now or now_ts()
    _protected_temp(conn, protect)
    tiers = {r[0]: r[1] for r in conn.execute("SELECT address,tier FROM contracts WHERE chain=?", (chain,))}
    old = []
    for addr, last in conn.execute("SELECT address, MAX(ts) FROM evidence e WHERE chain=? AND NOT EXISTS (SELECT 1 FROM "
                                   "_protect p WHERE p.chain=? AND p.address=e.address) GROUP BY address", (chain, chain)):
        ttl = T3_TTL_SEC if tiers.get(addr) else UNTIERED_TTL_SEC
        if last is not None and now - last > ttl:
            old.append(addr)
    for a in old:
        conn.execute("DELETE FROM evidence WHERE chain=? AND address=?", (chain, a))
        conn.execute("DELETE FROM drains WHERE chain=? AND drainer=?", (chain, a))
        conn.execute("DELETE FROM payouts WHERE chain=? AND drainer=?", (chain, a))
    return len(old)


def maybe_vacuum(conn, share=VACUUM_FREE_SHARE):
    """VACUUM when more than `share` of the pages are free (after a large prune); cheap check otherwise."""
    free = conn.execute("PRAGMA freelist_count").fetchone()[0]
    pages = conn.execute("PRAGMA page_count").fetchone()[0] or 1
    if free / pages <= share:
        return False
    conn.commit()
    try:
        conn.execute("VACUUM")
    except sqlite3.OperationalError as e:
        log.warning("vacuum failed: %s", e)
        return False
    return True


def run(conn, chain, seeds=None, protect=None, now=None):
    """All retention steps for one chain. protect: T1/T2 of the main database (None = skip step 3)."""
    now = now or now_ts()
    keep = local_protected(conn, chain, seeds) | (protect or set())
    st = dict(approvals_dedup=dedupe_approvals(conn, chain))
    st["public_spenders"] = len(public_spenders(conn, chain, keep, now))
    st["pko_pruned"] = compact_pko(conn, chain)
    st["g_funds_pruned"] = cap_g_funds(conn, chain)
    st["flows_pruned"] = prune_flows(conn, chain, now)
    if protect is not None:
        st["subjects_expired"] = expire_subjects(conn, chain, keep, now)
        st["evidence_pruned"] = compact_unprotected(conn, chain, keep)
    conn.commit()
    st["vacuum"] = maybe_vacuum(conn)
    log.info("%s: retention %s", chain, st)
    return st
