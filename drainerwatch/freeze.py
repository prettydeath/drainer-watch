"""'Freezable now': issuer-freezable stablecoin balances held by drainer infrastructure (T1/T2 subjects, their payout
wallets and cluster-shared wallets). Balances and blacklist status are read with eth_call (JSON-RPC batch on EVM,
triggerconstantcontract on TRON), cached FREEZE_CACHE_SEC in sqlite; render publishes `freezable` / `freezable_total`
from the cache only. BSC USDT (Binance-Peg BSC-USD) is not a Tether token and has no issuer freeze: not queried."""
import logging
import time
from collections import defaultdict

from .util import now_ts

log = logging.getLogger("drainerwatch.freeze")

# chain -> [(token, symbol, decimals, issuer, blacklist selector)] ; selectors: Tether isBlackListed(address) 0xe47d6060
# (Ethereum and TRON USDT, checked on both contracts), Circle isBlacklisted(address) 0xfe575a87
FREEZABLE = {
    "eth": [("0xdac17f958d2ee523a2206206994597c13d831ec7", "USDT", 6, "Tether", "e47d6060"),
            ("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "USDC", 6, "Circle", "fe575a87")],
    "base": [("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "USDC", 6, "Circle", "fe575a87")],
    "tron": [("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "USDT", 6, "Tether", "e47d6060")],
}
SEL_BALANCE = "70a08231"
FREEZE_ROLES = ("operator", "affiliate", "collector", "customer", "worker", "funder")
FREEZE_MAX_ADDRS = 300
FREEZE_CACHE_SEC = 30 * 60
FREEZE_MIN_USD = 100.0
FREEZE_TIME_BOX = 45            # seconds per run

DDL = """CREATE TABLE IF NOT EXISTS freeze_cache (chain TEXT NOT NULL, address TEXT NOT NULL, token TEXT NOT NULL,
    balance TEXT, frozen INTEGER, checked_at INTEGER, PRIMARY KEY (chain, address, token));"""


def ensure_table(conn):
    conn.executescript(DDL)


def targets(conn):
    """[(chain, address, role, drainer, drainer_tier)] for chains with freezable tokens, best tier / newest first.
    An address linked to several subjects keeps its best-tier link."""
    rows = conn.execute("SELECT chain,address,tier,last_seen FROM contracts WHERE tier IN ('T1','T2') "
                        "ORDER BY tier, last_seen DESC").fetchall()
    tier = {(r["chain"], r["address"]): r["tier"] for r in rows}
    out = {}
    for r in rows:
        if r["chain"] in FREEZABLE:
            out.setdefault((r["chain"], r["address"]), (r["chain"], r["address"], "drainer", r["address"], r["tier"]))
    q = "SELECT chain,drainer,wallet,role FROM payouts WHERE role IN (%s)" % ",".join("?" * len(FREEZE_ROLES))
    pays = sorted((p for p in conn.execute(q, FREEZE_ROLES) if (p["chain"], p["drainer"]) in tier
                   and p["chain"] in FREEZABLE), key=lambda p: tier[(p["chain"], p["drainer"])])
    for p in pays:
        out.setdefault((p["chain"], p["wallet"]), (p["chain"], p["wallet"], p["role"], p["drainer"],
                                                   tier[(p["chain"], p["drainer"])]))
    return sorted(out.values(), key=lambda x: x[4])     # stable: T1 before T2, original order inside a tier


def _word(chain, addr):
    if chain == "tron":
        from .tron import to_hex
        h = to_hex(addr) or ""
        return h[-40:].rjust(64, "0")
    return addr[2:].lower().rjust(64, "0")


def _int(res):
    if not res or not isinstance(res, str) or not res.startswith("0x") or len(res) != 66:
        return None
    try:
        return int(res, 16)
    except ValueError:
        return None


def refresh(conn, rpcs, max_addrs=FREEZE_MAX_ADDRS, time_box=FREEZE_TIME_BOX, now=None):
    """Query balance + blacklist status for up to `max_addrs` targets whose cache is older than FREEZE_CACHE_SEC.
    rpcs: chain -> client with eth_call_many([(to, data)]). Returns the number of (address, token) pairs refreshed."""
    now = now or now_ts()
    ensure_table(conn)
    t_end = time.monotonic() + time_box
    fresh = {(r["chain"], r["address"]) for r in conn.execute(
        "SELECT chain,address FROM freeze_cache GROUP BY chain,address HAVING MIN(checked_at) > ?",
        (now - FREEZE_CACHE_SEC,))}
    todo = [t for t in targets(conn) if (t[0], t[1]) not in fresh][:max_addrs]
    by_chain = defaultdict(list)
    for t in todo:
        if t[0] in rpcs:
            by_chain[t[0]].append(t[1])
    n = 0
    for chain, addrs in by_chain.items():
        for i in range(0, len(addrs), 25):
            if time.monotonic() > t_end:
                log.info("freezable: time box reached")
                conn.commit()
                return n
            part = addrs[i:i + 25]
            calls = [(tok, "0x" + sel + _word(chain, a)) for a in part for tok, _, _, _, bl in FREEZABLE[chain]
                     for sel in (SEL_BALANCE, bl)]
            try:
                res = rpcs[chain].eth_call_many(calls)
            except Exception as e:  # noqa: BLE001 - best effort, never breaks the run
                log.info("freezable %s: calls failed: %s", chain, e)
                break
            k = 0
            for a in part:
                for tok, *_ in FREEZABLE[chain]:
                    bal, fr = _int(res[k]), _int(res[k + 1])
                    k += 2
                    conn.execute("INSERT OR REPLACE INTO freeze_cache VALUES(?,?,?,?,?,?)",
                                 (chain, a, tok, None if bal is None else str(bal), None if fr is None else int(bool(fr)), now))
                    n += 1
    conn.commit()
    return n


def payload(conn, min_usd=FREEZE_MIN_USD):
    """(freezable list sorted by usd desc, freezable_total {issuer: usd not yet frozen}) from the cache."""
    ensure_table(conn)
    tokens = {(ch, t[0]): t for ch, ts in FREEZABLE.items() for t in ts}
    link = {(t[0], t[1]): t for t in targets(conn)}
    out, total = [], defaultdict(float)
    for r in conn.execute("SELECT * FROM freeze_cache WHERE balance IS NOT NULL"):
        t = tokens.get((r["chain"], r["token"]))
        lk = link.get((r["chain"], r["address"]))
        if not t or not lk:
            continue
        usd = int(r["balance"]) / 10 ** t[2]                  # issuer stablecoins: 1 unit = 1 USD
        if usd < min_usd:
            continue
        frozen = None if r["frozen"] is None else bool(r["frozen"])
        out.append(dict(chain=r["chain"], address=r["address"], role=lk[2], drainer=lk[3], drainer_tier=lk[4],
                        token=r["token"], symbol=t[1], issuer=t[3], balance=f"{usd:.2f}", usd=round(usd, 2),
                        already_frozen=frozen, checked_at=r["checked_at"]))
        if not frozen:
            total[t[3]] += usd
    out.sort(key=lambda x: -x["usd"])
    return out, {k: round(v, 2) for k, v in sorted(total.items())}
