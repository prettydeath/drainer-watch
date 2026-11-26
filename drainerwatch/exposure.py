"""Live exposure of approval-based subjects and subject facts resolved every run (cli run; render reads caches only).

* `is_contract` for every T1/T2 subject (eth_getCode / TRON getcontractinfo), stored in `codes` (size 0 = account) and
  on the `contracts` row, so a T1/T2 never shows an unknown code status.
* `subject_info`: tx count (nonce) of EVM T1/T2 approval spenders; a fresh EOA (nonce <= 3, no code) that received kit-
  amount approvals is the MS Drainer Wallet-Randomizer one-shot spender (`oneshot_spender` label, rollup).
* `open_allowances` per subject: current allowance(victim -> spender) and the victim's balance of that token for every
  approval-based evidence (approval_fingerprint, dust_approve, tron_approval), usd_at_risk = min(allowance, balance)
  priced where the token has a price; cached EXPOSURE_CACHE_SEC, <= EXPOSURE_MAX_CHECKS pairs per run."""
import json
import logging
import time
from collections import defaultdict

from .freeze import _int, _word
from .util import now_ts

log = logging.getLogger("drainerwatch.exposure")

APPROVAL_EVIDENCE = ("approval_fingerprint", "dust_approve", "tron_approval")
SEL_ALLOWANCE, SEL_BALANCE = "dd62ed3e", "70a08231"
EXPOSURE_MAX_CHECKS = 200
EXPOSURE_CACHE_SEC = 30 * 60
EXPOSURE_TIME_BOX = 40
MAX_CODE_CHECKS = 200
CODE_TIME_BOX = 60              # seconds per run for code + nonce lookups (TRON fallback node: seconds per address)
CODE_CHUNK = 10
UNLIMITED = 10 ** 36            # far above any real supply: shown as 'unlimited' (uint256 max, kit amounts)
ONESHOT_MAX_NONCE = 3

DDL = """
CREATE TABLE IF NOT EXISTS exposure_cache (chain TEXT NOT NULL, spender TEXT NOT NULL, victim TEXT NOT NULL,
    token TEXT NOT NULL, allowance TEXT, balance TEXT, usd REAL, checked_at INTEGER,
    PRIMARY KEY (chain, spender, victim, token));
CREATE TABLE IF NOT EXISTS subject_info (chain TEXT NOT NULL, address TEXT NOT NULL, nonce INTEGER, checked_at INTEGER,
    PRIMARY KEY (chain, address));
"""


def ensure_tables(conn):
    conn.executescript(DDL)


def approval_pairs(conn, tiers=("T1", "T2")):
    """[(chain, spender, victim, token)] from approval-based evidence of flagged subjects (newest first)."""
    q = ("SELECT e.chain,e.address,e.detail FROM evidence e JOIN contracts c ON c.chain=e.chain AND c.address=e.address "
         "WHERE e.type IN (%s) AND c.tier IN (%s) ORDER BY c.tier, e.ts DESC" %
         (",".join("?" * len(APPROVAL_EVIDENCE)), ",".join("?" * len(tiers))))
    out = []
    for r in conn.execute(q, APPROVAL_EVIDENCE + tuple(tiers)):
        d = json.loads(r["detail"] or "{}")
        if d.get("victim") and d.get("token"):
            out.append((r["chain"], r["address"], d["victim"], d["token"]))
    return list(dict.fromkeys(out))


def resolve_codes(conn, rpcs, cap=MAX_CODE_CHECKS, time_box=CODE_TIME_BOX):
    """eth_getCode for T1/T2 subjects without a code record; writes codes (size 0 for accounts) and contracts.is_contract.
    Looked up in chunks inside `time_box`; the rest stays without a code record and is picked up next run."""
    todo = conn.execute("SELECT c.chain,c.address FROM contracts c LEFT JOIN codes k ON k.chain=c.chain AND "
                        "k.address=c.address WHERE c.tier IN ('T1','T2') AND k.address IS NULL ORDER BY c.tier, "
                        "c.last_seen DESC LIMIT ?", (cap,)).fetchall()
    by = defaultdict(list)
    for r in todo:
        if r["chain"] in rpcs:
            by[r["chain"]].append(r["address"])
    n = 0
    from .bytecode import analyze, is_delegated_eoa
    t_end = time.monotonic() + time_box
    for ch, addrs in by.items():
        got = {}
        for i in range(0, len(addrs), CODE_CHUNK):
            if time.monotonic() > t_end:
                log.info("%s: code lookups: time box reached (%d/%d)", ch, i, len(addrs))
                break
            try:
                got.update(rpcs[ch].get_code_many(addrs[i:i + CODE_CHUNK]))
            except Exception as e:  # noqa: BLE001
                log.info("%s: code lookups failed: %s", ch, e)
                break
        for a, c in got.items():
            if c is None:
                continue
            eoa = c in ("0x", "") or is_delegated_eoa(c)
            info = analyze(c) if not eoa else dict(code_hash=None, size=0, skeleton=None, selectors=[])
            conn.execute("INSERT OR REPLACE INTO codes(chain,address,code_hash,size,skeleton,selectors) VALUES(?,?,?,?,?,?)",
                         (ch, a, info["code_hash"], info["size"], info["skeleton"], json.dumps(info["selectors"])))
            conn.execute("UPDATE contracts SET is_contract=?, code_size=? WHERE chain=? AND address=?",
                         (0 if eoa else 1, info["size"], ch, a))
            n += 1
    conn.commit()
    return n


def resolve_nonces(conn, rpcs, now=None):
    """Tx count of EVM approval spenders that are accounts (codes size 0), cached 1 h."""
    now = now or now_ts()
    ensure_tables(conn)
    spenders = sorted({(c, s) for c, s, _, _ in approval_pairs(conn) if c != "tron" and c in rpcs})
    fresh = {(r["chain"], r["address"]) for r in conn.execute("SELECT chain,address FROM subject_info WHERE checked_at>?",
                                                              (now - 3600,))}
    by = defaultdict(list)
    for c, s in spenders:
        k = conn.execute("SELECT size FROM codes WHERE chain=? AND address=?", (c, s)).fetchone()
        if (c, s) not in fresh and k is not None and not k["size"]:
            by[c].append(s)
    for c, addrs in by.items():
        try:
            got = rpcs[c].nonces(addrs[:MAX_CODE_CHECKS])
        except Exception as e:  # noqa: BLE001
            log.info("%s: nonce lookups failed: %s", c, e)
            continue
        for a, n in got.items():
            if n is not None:
                conn.execute("INSERT OR REPLACE INTO subject_info VALUES(?,?,?,?)", (c, a, n, now))
    conn.commit()


def refresh(conn, rpcs, tokens_of=None, prices=None, cap=EXPOSURE_MAX_CHECKS, time_box=EXPOSURE_TIME_BOX, now=None):
    """allowance + victim balance for approval pairs whose cache is older than EXPOSURE_CACHE_SEC.
    tokens_of(chain) -> Tokens-like with get(token) -> (symbol, decimals); prices: Prices-like (usd()). Best effort."""
    now = now or now_ts()
    ensure_tables(conn)
    t_end = time.monotonic() + time_box
    fresh = {(r["chain"], r["spender"], r["victim"], r["token"]) for r in conn.execute(
        "SELECT chain,spender,victim,token FROM exposure_cache WHERE checked_at>?", (now - EXPOSURE_CACHE_SEC,))}
    todo = [p for p in approval_pairs(conn) if p not in fresh and p[0] in rpcs][:cap]
    by = defaultdict(list)
    for p in todo:
        by[p[0]].append(p)
    n = 0
    for ch, pairs in by.items():
        for i in range(0, len(pairs), 25):
            if time.monotonic() > t_end:
                conn.commit()
                return n
            part = pairs[i:i + 25]
            calls = []
            for _, sp, v, tok in part:
                calls += [(tok, "0x" + SEL_ALLOWANCE + _word(ch, v) + _word(ch, sp)), (tok, "0x" + SEL_BALANCE + _word(ch, v))]
            try:
                res = rpcs[ch].eth_call_many(calls)
            except Exception as e:  # noqa: BLE001
                log.info("exposure %s: calls failed: %s", ch, e)
                break
            for j, (_, sp, v, tok) in enumerate(part):
                al, bal = _int(res[2 * j]), _int(res[2 * j + 1])
                usd = None
                if al is not None and bal is not None and prices is not None and tokens_of is not None:
                    try:
                        dec = tokens_of(ch).get(tok)[1]
                        usd = prices.usd(ch, tok, min(al, bal), dec)
                    except Exception:  # noqa: BLE001
                        usd = None
                conn.execute("INSERT OR REPLACE INTO exposure_cache VALUES(?,?,?,?,?,?,?,?)",
                             (ch, sp, v, tok, None if al is None else str(al), None if bal is None else str(bal), usd, now))
                n += 1
    conn.commit()
    return n


def payload(conn):
    """({(chain, subject): [open allowance rows]}, {(chain, subject): pulled}, exposure_total_usd)."""
    ensure_tables(conn)
    sym = {(r["chain"], r["address"]): (r["symbol"], r["decimals"]) for r in conn.execute("SELECT * FROM tokens")}
    pulled_pairs = {(r["chain"], r["drainer"], r["victim"]) for r in conn.execute("SELECT DISTINCT chain,drainer,victim FROM drains")}
    pulled_any = {(c, d) for c, d, _ in pulled_pairs}
    out, total = defaultdict(list), 0.0
    for r in conn.execute("SELECT * FROM exposure_cache ORDER BY usd DESC"):
        if r["allowance"] is None or int(r["allowance"]) == 0:
            continue
        al = int(r["allowance"])
        s, dec = sym.get((r["chain"], r["token"]), (None, None))
        bal = None if r["balance"] is None else int(r["balance"])
        out[(r["chain"], r["spender"])].append(dict(
            victim=r["victim"], token=r["token"], symbol=s,
            allowance="unlimited" if al >= UNLIMITED else str(al),
            victim_balance=None if bal is None else (str(bal) if dec is None else f"{bal / 10 ** dec:.6g}"),
            usd_at_risk=r["usd"], pulled=(r["chain"], r["spender"], r["victim"]) in pulled_pairs, checked_at=r["checked_at"]))
        total += r["usd"] or 0
    return out, {k: True for k in pulled_any}, round(total, 2)
