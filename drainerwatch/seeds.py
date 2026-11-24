"""Seed addresses: ScamSniffer blacklist (chain-agnostic) + operator-supplied data/seeds.csv."""
import csv
import logging

from .constants import ALLOWLIST_CSV, CHAINS, SCAMSNIFFER_URL, SEEDS_CSV, SEEDS_REFRESH_SEC
from .db import meta_get, meta_set
from .util import http_json, iso, norm_addr, now_ts

log = logging.getLogger("drainerwatch.seeds")


class SeedSet:
    """address -> {chain|None -> (label, source)}; chain None = valid on every chain."""

    def __init__(self, rows=()):
        self.by_addr: dict[str, dict] = {}
        for r in rows:
            self.by_addr.setdefault(r[0], {})[r[1]] = (r[2], r[3])

    def get(self, chain, addr):
        d = self.by_addr.get(addr)
        if not d:
            return None
        return d.get(chain) or d.get(None)

    def has(self, chain, addr):
        return self.get(chain, addr) is not None

    def addresses(self, chain):
        return [a for a, d in self.by_addr.items() if chain in d or None in d]

    def __len__(self):
        return len(self.by_addr)


def read_local_csv(path=SEEDS_CSV):
    out = []
    if not path.exists():
        return out
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            ch = (r.get("chain") or "").strip().lower() or None
            a = norm_addr(r.get("address"), ch)
            if not a or (ch and ch not in CHAINS):
                continue
            out.append((a, ch, (r.get("label") or "local seed").strip(), "local"))
    return out


FP_CHAIN_IDS = {"1": "eth", "56": "bsc", "8453": "base"}
_FP_CACHE = {}


def fp_list_dir():
    """Directory of the optional public false-positive lists (scam-detector fp_list.csv, failsafe_wallets.csv): env
    DRAINERWATCH_FP_DIR, else the private dataset folder when present. Never committed (third-party data)."""
    import os
    from pathlib import Path
    from .constants import FP_LIST_DIR_ENV, ROOT
    d = os.environ.get(FP_LIST_DIR_ENV)
    p = Path(d) if d else ROOT / "tests" / "backtest" / "private" / "datasets" / "starter-kits" / "scam-detector-py"
    return p if p.is_dir() else None


def load_fp_lists(chain, directory=None):
    """{address: source tag} from the public FP lists for one chain (fp_list.csv: address,chain_id,comment;
    failsafe_wallets.csv: address,chain_id,comment without header). Cached per (dir, chain)."""
    d = directory or fp_list_dir()
    if d is None:
        return {}
    key = (str(d), chain)
    if key in _FP_CACHE:
        return _FP_CACHE[key]
    out = {}
    for name, tag in (("fp_list.csv", "fp_list"), ("failsafe_wallets.csv", "failsafe")):
        f = d / name
        if not f.exists():
            continue
        with open(f, newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if len(row) < 2 or not row[0].strip().lower().startswith("0x"):
                    continue
                if FP_CHAIN_IDS.get(row[1].strip()) == chain:
                    a = norm_addr(row[0].strip(), "evm")
                    if a:
                        out[a] = f"{tag}: {(row[2] if len(row) > 2 else '').strip()}"
    _FP_CACHE[key] = out
    return out


def load_allowlist(chain, path=ALLOWLIST_CSV):
    """Operator additions to the allowlist: data/allowlist.csv (chain,address,note); empty chain = all chains. Plus the
    optional public FP lists (load_fp_lists)."""
    out = set(load_fp_lists(chain)) if chain != "tron" and path == ALLOWLIST_CSV else set()
    if path.exists():
        with open(path, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                ch = (r.get("chain") or "").strip().lower()
                a = norm_addr(r.get("address"), ch or None)
                if a and (not ch or ch == chain):
                    out.add(a)
    return out


def fetch_scamsniffer():
    data = http_json("GET", SCAMSNIFFER_URL, retries=3, timeout=60, validate=lambda o: isinstance(o, list))
    return [a for a in (norm_addr(x, "evm") for x in data) if a]


def refresh(conn, force=False, now=None):
    """Re-read the local CSV on every call; refresh ScamSniffer at most once per 6 h. Returns SeedSet."""
    now = now or now_ts()
    last = int(meta_get(conn, "seeds_ss_at", "0") or 0)
    if force or now - last >= SEEDS_REFRESH_SEC:
        try:
            addrs = fetch_scamsniffer()
            conn.execute("DELETE FROM seeds WHERE source='scamsniffer'")
            conn.executemany("INSERT OR IGNORE INTO seeds(address,chain,label,source,added) VALUES(?,?,?,?,?)",
                             [(a, None, "ScamSniffer blacklist", "scamsniffer", iso(now)) for a in addrs])
            meta_set(conn, "seeds_ss_at", now)
            log.info("seeds: scamsniffer %d addresses", len(addrs))
        except Exception as e:  # noqa: BLE001 - keep the previous seeds
            log.warning("seeds: scamsniffer refresh failed: %s", e)
    conn.execute("DELETE FROM seeds WHERE source='local'")
    conn.executemany("INSERT OR IGNORE INTO seeds(address,chain,label,source,added) VALUES(?,?,?,?,?)",
                     [(a, ch, lb, src, iso(now)) for a, ch, lb, src in read_local_csv()])
    conn.commit()
    return load(conn)


def load(conn):
    return SeedSet((r["address"], r["chain"], r["label"], r["source"])
                   for r in conn.execute("SELECT address,chain,label,source FROM seeds"))
