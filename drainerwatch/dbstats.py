"""Database size diagnostics: rows and bytes per table (dbstat when compiled in, else column-length estimate)."""
import logging

log = logging.getLogger("drainerwatch.dbstats")


def _tables(conn):
    return [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]


def table_stats(conn):
    """[(table, rows, bytes incl. its indexes or None)] sorted by bytes, then rows."""
    sizes = {}
    try:
        idx = {r[0]: r[1] for r in conn.execute("SELECT name,tbl_name FROM sqlite_master WHERE type IN ('table','index')")}
        for name, nbytes in conn.execute("SELECT name, SUM(pgsize) FROM dbstat GROUP BY name"):
            t = idx.get(name, name)
            if t.startswith("sqlite_autoindex_"):
                t = t.split("_", 3)[-1].rsplit("_", 1)[0]
            sizes[t] = sizes.get(t, 0) + (nbytes or 0)
    except Exception:  # noqa: BLE001 - dbstat not compiled in: estimate from column lengths
        for t in _tables(conn):
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({t})")]
            if cols:
                expr = "+".join(f"COALESCE(length({c}),0)" for c in cols)
                sizes[t] = conn.execute(f"SELECT COALESCE(SUM({expr}),0) FROM {t}").fetchone()[0]
    out = []
    for t in _tables(conn):
        out.append((t, conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0], sizes.get(t)))
    out.sort(key=lambda x: (-(x[2] or 0), -x[1]))
    return out


def evidence_stats(conn):
    """[(type, rows, detail bytes, distinct subjects)] of the evidence table, largest first."""
    try:
        return [tuple(r) for r in conn.execute(
            "SELECT type, COUNT(*), COALESCE(SUM(length(detail)),0), COUNT(DISTINCT chain||address) FROM evidence "
            "GROUP BY type ORDER BY 3 DESC")]
    except Exception:  # noqa: BLE001
        return []


def report(conn, name=""):
    lines = [f"db stats {name}:"]
    for t, n, b in table_stats(conn):
        lines.append(f"  {t:<22} rows {n:>11,}  bytes {'?' if b is None else f'{b / 1e6:,.1f} MB'}")
    ev = evidence_stats(conn)
    if ev:
        lines.append("  evidence by type (rows / detail MB / subjects):")
        for t, n, b, s in ev:
            lines.append(f"    {t:<26} {n:>10,}  {b / 1e6:>8.1f} MB  {s:>9,}")
    return "\n".join(lines)
