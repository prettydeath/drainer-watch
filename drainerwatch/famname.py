"""Human names for code families (data.json `family_name` + `family_name_source`; the hash stays in `family`).

Priority: 1) kit fingerprint -> kit name; 2) the name members give themselves (most common Etherscan-verified
ContractName, or the TRON contract `name`), marked as self-named when it imitates a well-known protocol; 3) ERC-20 token
name / symbol; 4) the 1-2 most distinctive non-standard dispatcher functions (selectors resolved via the public openchain
signature database, cached); 5) "Unnamed code family <hash>". names_for() only reads caches (render); resolve() fills
the caches over the network within a per-run budget (cli run)."""
import json
import logging
from collections import Counter, defaultdict

from .bytecode import kit_family
from .constants import ERC20_SELECTORS
from .util import http_json, now_ts

log = logging.getLogger("drainerwatch.famname")

SOURCES = ("kit", "contract_name", "token_name", "functions", "hash")
KIT_NAMES = {
    "ms_drainer": "MS Drainer", "trusty_v1": "Trusty v1 (MS Drainer public contract)", "ms_new": "MS_NEW (MS Drainer)",
    "ms_generated": "MS generated bait", "verify_account": "VerifyAccount", "owner_collector": "OwnerCollector",
    "ms_oneshot_spender": "MS Drainer one-shot spender (wallet randomizer)", "buytron_swap_trx": "buytron SwapTRX", "buytron_swap_proxy": "buytron SwapProxy", "tron_1e46": "TRON 10^46 approval kit", "tron_sweeper": "TRON sweeper kit (trc20Withdraw / registerProxy / sweep markers)",
}
# well-known protocols / assets: a flagged contract calling itself like this is an impersonation, not the real one
FAMOUS = ["SunSwap", "JustLend", "Uniswap", "PancakeSwap", "SushiSwap", "1inch", "OpenSea", "Seaport", "Permit2", "Tether",
          "USDT", "USDC", "Circle", "Aave", "Compound", "Curve", "Lido", "MetaMask", "TronLink", "Binance", "Coinbase",
          "Ledger", "Trust Wallet", "Blur", "Safe", "Gnosis", "Chainlink", "Arbitrum", "Optimism", "LayerZero", "Wormhole"]
# selectors too common to name a family (ERC-20 / ownable / proxy / multicall / receive helpers)
COMMON_SELECTORS = set(ERC20_SELECTORS) | {
    "8da5cb5b", "f2fde38b", "715018a6", "13af4035", "06fdde03", "95d89b41", "313ce567", "01ffc9a7", "3659cfe6",
    "4f1ef286", "5c60da1b", "f851a440", "8f283970", "ac9650d8", "252dba42", "82ad56cb", "3ccfd60b", "2e1a7d4d",
    "d0e30db0", "150b7a02", "f23a6e61", "bc197c81", "39509351", "a457c2d7", "d505accf", "7ecebe00", "3644e515",
    "40c10f19", "42966c68", "79cc6790", "8456cb59", "3f4ba83a", "5c975abb", "1626ba7e", "e30c3978", "79ba5097"}
SIG_API = "https://api.openchain.xyz/signature-database/v1/lookup"
SIG_BATCH = 40
SIG_RECHECK = 14 * 86400
MAX_SIG_LOOKUPS = 200          # selectors resolved per run
MAX_TOKEN_CALLS = 40           # token name()/symbol() eth_calls per run

DDL = """
CREATE TABLE IF NOT EXISTS sig_names (selector TEXT PRIMARY KEY, name TEXT, checked_at INTEGER);
CREATE TABLE IF NOT EXISTS token_names (chain TEXT NOT NULL, address TEXT NOT NULL, name TEXT, symbol TEXT,
    checked_at INTEGER, PRIMARY KEY (chain, address));
"""


def ensure_tables(conn):
    conn.executescript(DDL)


def impersonation(name, legit=False):
    """'self-named "X" (not the real Y)' when a flagged contract calls itself after a famous protocol, else None."""
    if legit or not name:
        return None
    low = name.lower()
    for f in FAMOUS:
        if f.lower() in low:
            return f'self-named "{name}" (not the real {f})'
    return None


def short_fn(sig):
    return (sig or "").split("(")[0]


def functions_name(selector_sets, sig):
    """1-2 most distinctive non-standard functions: selectors present in most members, rarest name first never needed;
    ties broken by name. selector_sets: [set]; sig: selector -> 'name(args)' or ''. Returns 'A/B contract' or None."""
    cnt = Counter(s for ss in selector_sets for s in set(ss) if s not in COMMON_SELECTORS)
    named = [(n, short_fn(sig.get(s))) for s, n in cnt.items() if sig.get(s)]
    named = [(n, f) for n, f in named if f and f.lower() not in {"owner", "fallback", "receive"}]
    if not named:
        return None
    named.sort(key=lambda x: (-x[0], x[1]))
    picks = list(dict.fromkeys(f for _, f in named))[:2]
    return "/".join(picks) + " contract"


def pick(family, members):
    """members: [dict(kit, contract_name, legit, token_name, token_symbol, selectors)] -> (name, source)."""
    if family in KIT_NAMES:
        return KIT_NAMES[family], "kit"
    kits = Counter(m["kit"] for m in members if m.get("kit"))
    if kits:
        k = kits.most_common(1)[0][0]
        return KIT_NAMES.get(k, k), "kit"
    names = Counter(m["contract_name"].strip() for m in members if (m.get("contract_name") or "").strip())
    if names:
        nm = sorted(names.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        return impersonation(nm, any(m.get("legit") for m in members if m.get("contract_name") == nm)) or nm, "contract_name"
    toks = Counter((m.get("token_name") or m.get("token_symbol")) for m in members
                   if m.get("token_name") or m.get("token_symbol"))
    if toks:
        nm = sorted(toks.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
        return (impersonation(nm) or f"token {nm}"), "token_name"
    fn = functions_name([m.get("selectors") or () for m in members], members[0].get("sig") or {}) if members else None
    if fn:
        return fn, "functions"
    tail = family[2:] if family.startswith("f_") else family
    return f"Unnamed code family {tail}", "hash"


# ---------- cache readers (render) ----------
def _members(conn, contracts):
    ensure_tables(conn)
    names = {}
    for r in conn.execute("SELECT chain,address,verified,name,proxy,impl_name,impl_verified FROM verified_cache"):
        nm = r["impl_name"] if r["proxy"] and r["impl_verified"] else (r["name"] if r["verified"] else None)
        if nm:
            names[(r["chain"], r["address"])] = nm
    for r in conn.execute("SELECT address,name FROM tron_contracts WHERE name IS NOT NULL AND name != ''"):
        names[("tron", r["address"])] = r["name"]
    sels = {}
    for r in conn.execute("SELECT chain,address,selectors FROM codes"):
        sels[(r["chain"], r["address"])] = set(json.loads(r["selectors"] or "[]"))
    for r in conn.execute("SELECT address,selectors FROM tron_contracts WHERE selectors IS NOT NULL"):
        sels.setdefault(("tron", r["address"]), set(json.loads(r["selectors"] or "[]")))
    toks = {(r["chain"], r["address"]): (r["name"], r["symbol"]) for r in conn.execute("SELECT * FROM token_names")}
    sig = {r["selector"]: r["name"] for r in conn.execute("SELECT selector,name FROM sig_names")}
    fam = defaultdict(list)
    for c in contracts:
        if not c.get("family"):
            continue
        k = (c["chain"], c["address"])
        s = sels.get(k, set())
        t = toks.get(k, (None, None))
        fam[c["family"]].append(dict(kit=kit_family(s) if s else None, contract_name=names.get(k) or c.get("contract_name_raw"),
                                     legit=False, token_name=t[0], token_symbol=t[1], selectors=s, sig=sig,
                                     erc20=len(s & ERC20_SELECTORS) >= 4, chain=c["chain"], address=c["address"]))
    return fam


def names_for(conn, contracts):
    """{family: (name, source)} for every family present in `contracts` (data.json rows), from caches only."""
    return {f: pick(f, ms) for f, ms in _members(conn, contracts).items()}


# ---------- network resolution (cli run) ----------
def resolve(conn, rpcs=None, max_sigs=MAX_SIG_LOOKUPS, max_tokens=MAX_TOKEN_CALLS, now=None):
    """Fill sig_names / token_names for families that would otherwise fall back to functions / hash. Best effort."""
    now = now or now_ts()
    ensure_tables(conn)
    contracts = [dict(chain=r["chain"], address=r["address"], family=r["family"])
                 for r in conn.execute("SELECT chain,address,family FROM contracts WHERE family IS NOT NULL")]
    fam = _members(conn, contracts)
    need_tok, need_sig = [], set()
    for f, ms in fam.items():
        name, src = pick(f, ms)
        if src not in ("functions", "hash"):
            continue
        for m in ms:
            if m["erc20"] and m["chain"] != "tron" and m["chain"] in (rpcs or {}):
                need_tok.append((m["chain"], m["address"]))
        need_sig |= {s for m in ms for s in m["selectors"] if s not in COMMON_SELECTORS}
    _tokens(conn, rpcs or {}, need_tok[:max_tokens], now)
    fresh = {r["selector"] for r in conn.execute("SELECT selector FROM sig_names WHERE name != '' OR checked_at > ?",
                                                 (now - SIG_RECHECK,))}
    todo = sorted(need_sig - fresh)[:max_sigs]
    for i in range(0, len(todo), SIG_BATCH):
        part = todo[i:i + SIG_BATCH]
        try:
            res = http_json("GET", SIG_API, params={"function": ",".join("0x" + s for s in part), "filter": "true"},
                            interval=1.0, retries=2, timeout=30, validate=lambda o: isinstance(o, dict))
        except Exception as e:  # noqa: BLE001 - best effort
            log.info("signature lookup failed: %s", e)
            break
        found = ((res.get("result") or {}).get("function")) or {}
        for s in part:
            hits = found.get("0x" + s) or []
            conn.execute("INSERT OR REPLACE INTO sig_names VALUES(?,?,?)", (s, hits[0]["name"] if hits else "", now))
    conn.commit()


def _tokens(conn, rpcs, pairs, now):
    from .tokens import decode_symbol as decode_string
    have = {(r["chain"], r["address"]) for r in conn.execute("SELECT chain,address FROM token_names")}
    by_chain = defaultdict(list)
    for ch, a in pairs:
        if (ch, a) not in have:
            by_chain[ch].append(a)
    for ch, addrs in by_chain.items():
        try:
            res = rpcs[ch].eth_call_many([(a, d) for a in addrs for d in ("0x06fdde03", "0x95d89b41")])
        except Exception as e:  # noqa: BLE001
            log.info("%s: token name calls failed: %s", ch, e)
            continue
        for i, a in enumerate(addrs):
            nm, sy = decode_string(res[2 * i]), decode_string(res[2 * i + 1])
            conn.execute("INSERT OR REPLACE INTO token_names VALUES(?,?,?,?,?)", (ch, a, nm or None, sy or None, now))
    conn.commit()
