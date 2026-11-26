"""False-positive guard for large generic pulls (custodial sweeps that look like EOA-spender drains).

A 2026-11-26 audit of the 14 largest subjects by USD found every one of them to be a service, not a drainer: exchange
deposit sweepers (Kraken), BitGo WalletSimple, company hot wallets with operator keys, OTC settlement, and TRON
processors that sweep approved deposit addresses (68 % of all drain USD of the week). Their common shapes:

* repeat victim   - the same "victim" is pulled again and again on different days (a drain is a one-off: an emptied
                    wallet does not keep refilling for the same spender); not counted for subjects with a fee split;
* same owner      - the victim funded the spender / recipient, or the spender / recipient funded the victim (looked up
                    from the address's first incoming native transfers, so older links than the scan window count);
* deposit address - the victim's token history is a deposit address: many outgoing transfers to very few sinks, with
                    incoming deposits in between (looked up on Etherscan / TronGrid);
* Arkham entity   - (optional, ARKHAM_API_KEY) the spender, a victim or a non-deposit recipient is attributed by Arkham
                    Intel to a service entity (exchange, OTC desk, custodian, ...); Arkham-malicious subjects are never capped;
* round amounts   - two or more pulls >= FP_ROUND_MIN_USD with a round amount (multiple of 1000, optionally with a tiny
                    reference tag such as 4000000.0001) - how services move money, not how drainers empty balances;
* DEX pool        - the same wallet's tokens go into AMM pairs / pools (token0()+token1() dispatcher, verified Uniswap /
                    Pancake pair or pool, or a `dex` label) again and again on different days: trading through a router
                    or tax token, not a drain (a drainer swapping its loot hits a pool once per victim);
* aggregator      - the recipient collects from far more senders than the subject's victims (>= 100 senders and 5x the
                    victims in its last 200 token transfers): a service collecting deposits, the "drains" are a few of them;
* distributor     - the recipient pays out to >= 100 addresses from <= 3 sources: a withdrawal / payout hot wallet;
* pipeline        - the recipient is >= 180 days older than the subject's first drain, moved >= 5x the subject's USD out in
                    its last 200 token transfers and has <= 10 senders: a long-lived service pipe (drainers rotate wallets).

When legs with any of these shapes carry >= FP_SERVICE_SHARE of a subject's drain USD, the subject is capped at T3
(label `service_sweep_capped` plus one `fp_*` reason label each) and drops out of the headline totals. Subjects with a
kit fingerprint or other kit evidence (KIT_KEEP) are never capped. BitGo WalletSimple / Forwarder contracts are capped
by verified name (`custody_contract_capped`).
"""
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

from .util import env, http_json, key_pool, now_ts, redact

log = logging.getLogger(__name__)

FP_CHECK_MIN_USD = 50_000          # subjects below this are left alone (caps and lookups)
FP_SERVICE_SHARE = 0.6             # share of the subject's drain USD on service-shaped legs that caps it
FP_REPEAT_PULLS = 3                # repeat victim: pulled this many times ...
FP_REPEAT_DAYS = 2                 # ... on at least this many distinct UTC days
FP_ROUND_MIN_USD = 100_000         # a round pull counts from this size ...
FP_ROUND_MIN_LEGS = 2              # ... and only when the subject has at least this many of them
DEPOSIT_MIN_OUT = 10               # deposit address: >= this many outgoing token transfers ...
DEPOSIT_MAX_SINKS = 5              # ... to at most this many distinct addresses ...
DEPOSIT_MIN_IN = 5                 # ... with at least this many incoming ones
FP_MAX_SUBJECTS = 10               # history lookups per run: subjects (largest USD first) ...
FP_VICTIMS_PER_SUBJECT = 3         # ... their largest victims, plus the subject and its FP_RECIPIENTS largest recipients
FP_MAX_CALLS = 120                 # per chain kind (Etherscan / TronGrid) and run
FP_RECIPIENTS = 2                  # recipients looked up per subject (largest USD first)
POOL_MIN_PULLS = 5                 # DEX pool: a victim's pulls into pools, at least this many ...
POOL_MIN_DAYS = 2                  # ... on this many distinct UTC days
POOL_NAMES = ("UniswapV2Pair", "UniswapV3Pool", "PancakePair", "PancakeV3Pool", "UniswapV4Pool", "SushiSwapPair",
              "UniswapV2Pair_flattened", "AerodromePool", "Pool", "Pair", "CLPool", "AlgebraPool")
POOL_SELECTORS = {"0dfe1681", "d21220a7"}      # token0(), token1()
AGG_MIN_SENDERS = 100              # aggregator: >= this many distinct senders ...
AGG_VICTIM_RATIO = 5               # ... and this many times the subject's victims into that recipient
DIST_MIN_SINKS = 100               # distributor: >= this many distinct receivers ...
DIST_MAX_SOURCES = 3               # ... from at most this many senders
PIPE_MIN_AGE_SEC = 180 * 86400     # pipeline: recipient this much older than the subject's first drain ...
PIPE_VOLUME_RATIO = 5              # ... moved this many times the subject's USD into it out again (last 200 transfers) ...
PIPE_MAX_SENDERS = 10              # ... with at most this many distinct senders
STABLES = {"USDT", "USDC", "DAI", "FDUSD", "USDE", "TUSD", "USDD", "BUSD", "PYUSD", "USD1", "USDC.E"}
FP_TIME_BOX = 60                   # seconds for all lookups of one run
FP_RECHECK_SEC = 7 * 86400

TRONGRID = "https://api.trongrid.io"

# kit evidence: a subject carrying any of these is a drainer whatever its money looks like
KIT_KEEP = {"seed", "kit_signature", "approval_fingerprint", "kit_pull", "bait_payable", "bait_withdraw", "kit_confirmed",
            "kit_exact", "kit_public", "ms_deadline", "ms_deadline_pull", "batch_approval_drain", "kit_router_swap",
            "perm_hijack_drain", "perm_hijack_multi", "oneshot_multi", "oneshot_hub", "wa_scam", "prefund_approve",
            "prefund_approve_multi", "claimer_split", "foreign_swap_kit", "ms_cashback", "dust_approve_kit",
            "emergency_gas_kit", "owner_collect", "c2_config_intel", "vanity_drainer", "kit_deposit", "aml_approve_transfer"}
# fee splits (operator / affiliate shares) are a drainer trait: for such subjects a repeat victim alone is not a sweep (a
# drainer holding a standing allowance pulls again whenever the wallet refills); the other shapes still apply
SPLIT_LABELS = {"split_pull", "split_xtx", "share_grid", "kept_share"}
CUSTODY_NAMES = ("WalletSimple", "ForwarderV4", "Forwarder")   # BitGo multisig wallet and its deposit forwarders
FP_LABELS = ("fp_repeat_victim", "fp_same_owner", "fp_deposit_address", "fp_round_amounts")

# Arkham Intel (optional, ARKHAM_API_KEY): entity attribution of the subject, its main recipients and largest victims
ARKHAM_API = "https://api.arkm.com"
ARKHAM_MIN_USD = 250_000           # only subjects this large are sent to Arkham (label lookups are a metered quota)
ARKHAM_MAX_SUBJECTS = 40
ARKHAM_VICTIMS = 5
ARKHAM_RECIPIENTS = 2
ARKHAM_RECHECK_SEC = 30 * 86400
ARKHAM_CHAINS = {"eth": "ethereum", "bsc": "bsc", "base": "base", "tron": "tron", "polygon": "polygon",
                 "arbitrum": "arbitrum_one", "optimism": "optimism", "avalanche": "avalanche"}
# entity types that are services (besides Entity.service == true); "individual" and unknown types are not
ARKHAM_SERVICE_TYPES = {"cex", "otc", "custodian", "market-maker", "market_maker", "marketmaker", "payments",
                        "payment-processor", "fund", "bridge", "dex", "exchange"}
# Arkham calls it malicious: never capped, whatever the money looks like
ARKHAM_MALICIOUS_TYPES = {"scam", "scammer", "hacker", "hack", "exploit", "exploiter", "drainer", "phishing",
                          "sanctioned", "sanctions", "ransomware", "darknet", "mixer", "fraud"}
ARKHAM_MALICIOUS_WORDS = ("scam", "phish", "drainer", "exploit", "hacker", "fake_phishing")
ARKHAM_SCHEMA = ("CREATE TABLE IF NOT EXISTS arkham_cache(chain TEXT NOT NULL, address TEXT NOT NULL, entity TEXT, "
                 "entity_id TEXT, entity_type TEXT, service INTEGER, label TEXT, deposit_service TEXT, checked_at INTEGER, "
                 "PRIMARY KEY(chain, address))")

SCHEMA = ("CREATE TABLE IF NOT EXISTS addr_history(chain TEXT NOT NULL, address TEXT NOT NULL, funders TEXT, "
          "out_n INTEGER, out_sinks INTEGER, in_n INTEGER, checked_at INTEGER, in_senders INTEGER, out_usd REAL, "
          "created_at INTEGER, contract_name TEXT, PRIMARY KEY(chain, address))")
HISTORY_COLS = (("in_senders", "INTEGER"), ("out_usd", "REAL"), ("created_at", "INTEGER"), ("contract_name", "TEXT"))


def ensure_schema(conn):
    conn.execute(SCHEMA)
    have = {r[1] for r in conn.execute("PRAGMA table_info(addr_history)")}
    for col, typ in HISTORY_COLS:                       # tables created before these columns existed
        if col not in have:
            conn.execute(f"ALTER TABLE addr_history ADD COLUMN {col} {typ}")


# ---------- pure helpers ----------
def is_round(amount) -> bool:
    """Multiple of 1000 tokens, optionally with a fractional tag below 0.01 (4000000.0001, 300000)."""
    try:
        d = Decimal(str(amount))
    except (InvalidOperation, ValueError):
        return False
    whole = int(d)
    return whole >= 1000 and whole % 1000 == 0 and d - whole < Decimal("0.01")


def is_custody_name(name) -> bool:
    if not name:
        return False
    head = str(name).split(" (")[0].strip()
    impl = str(name).split("proxy of ")[-1].rstrip(")").strip() if "proxy of " in str(name) else ""
    return head in CUSTODY_NAMES or impl in CUSTODY_NAMES


def is_deposit_address(h) -> bool:
    return bool(h) and (h.get("out_n") or 0) >= DEPOSIT_MIN_OUT and 0 < (h.get("out_sinks") or 0) <= DEPOSIT_MAX_SINKS \
        and (h.get("in_n") or 0) >= DEPOSIT_MIN_IN


def arkham_malicious(x) -> bool:
    if not x:
        return False
    t = (x.get("entity_type") or "").lower()
    text = " ".join(str(x.get(k) or "") for k in ("entity", "label")).lower()
    return t in ARKHAM_MALICIOUS_TYPES or any(w in text for w in ARKHAM_MALICIOUS_WORDS)


def arkham_service(x) -> bool:
    """Attributed to a legitimate service entity (exchange, OTC desk, custodian, ...), deposit addresses included."""
    if not x or arkham_malicious(x):
        return False
    return bool(x.get("service")) or (x.get("entity_type") or "").lower() in ARKHAM_SERVICE_TYPES \
        or bool(x.get("deposit_service"))


def arkham_deposit(x) -> bool:
    """A service's deposit address (where a drainer may cash out), not its deposit sweeper / hot wallet."""
    lb = (x or {}).get("label") or ""
    return bool(x) and (bool(x.get("deposit_service")) or ("deposit" in lb.lower() and "sweep" not in lb.lower()))


def is_pool(name=None, selectors=None, category=None) -> bool:
    if category and str(category).lower() in ("dex", "amm"):
        return True
    if selectors and POOL_SELECTORS <= set(selectors):
        return True
    head = str(name or "").split(" (")[0].strip()
    return head in POOL_NAMES


def recipient_kind(h, victims_in, first_ts, usd_in):
    """Service shape of a recipient from its history: fp_aggregator / fp_distributor / fp_pipeline or None.
    victims_in: the subject's distinct victims whose tokens reached it; usd_in: the subject's USD into it."""
    if not h:
        return None
    snd, sinks = h.get("in_senders") or 0, h.get("out_sinks") or 0
    if snd >= AGG_MIN_SENDERS and snd >= AGG_VICTIM_RATIO * max(1, victims_in):
        return "fp_aggregator"
    if sinks >= DIST_MIN_SINKS and 0 < snd <= DIST_MAX_SOURCES:
        return "fp_distributor"
    created = h.get("created_at")
    if created and first_ts and first_ts - created >= PIPE_MIN_AGE_SEC and usd_in > 0 \
            and (h.get("out_usd") or 0) >= PIPE_VOLUME_RATIO * usd_in and 0 < snd <= PIPE_MAX_SENDERS:
        return "fp_pipeline"
    return None


def _day(ts):
    return datetime.fromtimestamp(int(ts or 0), tz=timezone.utc).date()


def service_legs(addr, legs, hist, repeat_counts=True, ark=None, pools=frozenset()):
    """legs: drain rows (victim, recipient, ts, amount, usd) of one subject; hist: address -> history dict (funders,
    out_n, out_sinks, in_n); ark: address -> Arkham attribution; repeat_counts=False ignores the repeat-victim shape.
    A victim attributed to a service, or a recipient that is a service wallet other than a deposit address (a drainer
    may cash out into an exchange deposit address, never into its hot wallet), makes the leg `fp_arkham_entity`.
    pools: recipients that are AMM pairs / pools. A recipient with an aggregator / distributor / pipeline history
    (recipient_kind) makes every leg into it service-shaped. Returns (service_usd, total_usd, reasons)."""
    ark = ark or {}
    first_ts = min((int(d["ts"] or 0) for d in legs), default=0)
    rkind = {}
    for rc in {d["recipient"] for d in legs if d["recipient"]}:
        into = [d for d in legs if d["recipient"] == rc]
        rkind[rc] = recipient_kind(hist.get(rc), len({d["victim"] for d in into}), first_ts,
                                   sum(float(d["usd"] or 0) for d in into))
    by_v = defaultdict(list)
    for d in legs:
        by_v[d["victim"]].append(d)
    total = sum(float(d["usd"] or 0) for d in legs)
    rounds = [d for d in legs if float(d["usd"] or 0) >= FP_ROUND_MIN_USD and is_round(d["amount"])]
    round_ok = len(rounds) >= FP_ROUND_MIN_LEGS
    sub_f = set((hist.get(addr) or {}).get("funders") or ())
    svc, reasons = 0.0, set()
    for v, ds in by_v.items():
        why = set()
        if repeat_counts and len(ds) >= FP_REPEAT_PULLS and len({_day(d["ts"]) for d in ds}) >= FP_REPEAT_DAYS:
            why.add("fp_repeat_victim")
        recips = {d["recipient"] for d in ds if d["recipient"]}
        vf = set((hist.get(v) or {}).get("funders") or ())
        rf = set().union(*[set((hist.get(r) or {}).get("funders") or ()) for r in recips]) if recips else set()
        if vf & ({addr} | recips) or v in sub_f | rf:
            why.add("fp_same_owner")
        if is_deposit_address(hist.get(v)):
            why.add("fp_deposit_address")
        pool_ds = [d for d in ds if d["recipient"] in pools]
        if len(pool_ds) >= POOL_MIN_PULLS and len({_day(d["ts"]) for d in pool_ds}) >= POOL_MIN_DAYS:
            why.add("fp_dex_pool")
        if arkham_service(ark.get(v)) or any(arkham_service(ark.get(r)) and not arkham_deposit(ark.get(r)) for r in recips):
            why.add("fp_arkham_entity")
        if why:
            svc += sum(float(d["usd"] or 0) for d in ds)
            reasons |= why
            continue
        for d in ds:                                    # leg by leg: the recipient's own shape, then round amounts
            k = rkind.get(d["recipient"])
            if k:
                svc += float(d["usd"] or 0)
                reasons.add(k)
            elif round_ok and d in rounds:
                svc += float(d["usd"] or 0)
                reasons.add("fp_round_amounts")
    return svc, total, reasons


# ---------- roll-up step ----------
def load_history(conn):
    ensure_schema(conn)
    out = {}
    for r in conn.execute("SELECT * FROM addr_history"):
        out[(r["chain"], r["address"])] = dict(funders=json.loads(r["funders"] or "[]"), out_n=r["out_n"],
                                               out_sinks=r["out_sinks"], in_n=r["in_n"], in_senders=r["in_senders"],
                                               out_usd=r["out_usd"], created_at=r["created_at"],
                                               contract_name=r["contract_name"])
    return out


def load_arkham(conn):
    conn.execute(ARKHAM_SCHEMA)
    return {(r["chain"], r["address"]): dict(entity=r["entity"], entity_id=r["entity_id"], entity_type=r["entity_type"],
                                             service=None if r["service"] is None else bool(r["service"]),
                                             label=r["label"], deposit_service=r["deposit_service"])
            for r in conn.execute("SELECT * FROM arkham_cache") if r["entity"] or r["label"] or r["deposit_service"]}


def pool_recipients(conn, chain, recips, hist):
    """Recipients that are AMM pairs / pools: code dispatcher (codes.selectors), verified name, or a dex label."""
    out = set()
    for rc in recips:
        sel = conn.execute("SELECT selectors FROM codes WHERE chain=? AND address=?", (chain, rc)).fetchone()
        lab = conn.execute("SELECT category FROM labels WHERE chain=? AND address=?", (chain, rc)).fetchone()
        if is_pool((hist.get(rc) or {}).get("contract_name"), json.loads(sel["selectors"] or "[]") if sel else None,
                   lab["category"] if lab else None):
            out.add(rc)
    return out


def apply_caps(conn, rows):
    """Cap service-shaped T1/T2 subjects at T3 (mutates rows). Returns the number capped."""
    hist_all = load_history(conn)
    ark_all = load_arkham(conn)
    n = 0
    for r in rows:
        if r["tier"] not in ("T1", "T2"):
            continue
        lb = set(r["labels"])
        if lb & KIT_KEEP:
            continue
        if is_custody_name(r.get("contract_name")):
            r["tier"], r["labels"] = "T3", sorted(lb | {"custody_contract_capped"})
            n += 1
            continue
        if (r.get("usd") or 0) < FP_CHECK_MIN_USD:
            continue
        ch = r["chain"]
        legs = [dict(x) for x in conn.execute("SELECT victim,recipient,ts,amount,usd FROM drains WHERE chain=? AND drainer=?",
                                              (ch, r["address"]))]
        if not legs:
            continue
        keys = {r["address"]} | {d["victim"] for d in legs} | {d["recipient"] for d in legs if d["recipient"]}
        hist = {k: hist_all[(ch, k)] for k in keys if (ch, k) in hist_all}
        ark = {k: ark_all[(ch, k)] for k in keys if (ch, k) in ark_all}
        recips = {d["recipient"] for d in legs if d["recipient"]}
        if any(arkham_malicious(ark.get(k)) for k in {r["address"]} | recips):
            r["labels"] = sorted(lb | {"arkham_malicious"})         # Arkham calls it a scammer: never capped
            continue
        if arkham_service(ark.get(r["address"])):
            r["tier"], r["labels"] = "T3", sorted(lb | {"fp_arkham_entity", "service_sweep_capped"})
            n += 1
            continue
        pools = pool_recipients(conn, ch, recips, hist)
        svc, total, reasons = service_legs(r["address"], legs, hist, repeat_counts=not lb & SPLIT_LABELS, ark=ark,
                                           pools=pools)
        if total > 0 and svc / total >= FP_SERVICE_SHARE:
            r["tier"], r["labels"] = "T3", sorted(lb | reasons | {"service_sweep_capped"})
            n += 1
    return n


# ---------- enrichment: history lookups ----------
class TronGrid:
    """TronGrid v1 account API (keyless works, throttled; TRONGRID_API_KEYS used when set)."""

    def __init__(self, cap=None):
        self.pool = key_pool("TRONGRID_API_KEYS")
        self.url = (env("TRONGRID_V1_URL") or TRONGRID).rstrip("/")
        self.calls, self.cap = 0, FP_MAX_CALLS if cap is None else cap

    def get(self, path, params):
        if self.calls >= self.cap:
            return None
        self.calls += 1
        key = self.pool.next() if len(self.pool) else None
        try:
            r = http_json("GET", self.url + path, params=params, headers={"TRON-PRO-API-KEY": key} if key else {},
                          interval=0.3 if key else 1.2, retries=3, timeout=30,
                          validate=lambda o: isinstance(o, dict) and "data" in o)
        except Exception as e:  # noqa: BLE001 - best effort
            log.debug("trongrid %s: %s", path, redact(e))
            return None
        return r.get("data")

    def history(self, a):
        from .tron import to_base58
        txs = self.get(f"/v1/accounts/{a}/transactions", dict(only_to="true", only_confirmed="true",
                                                             order_by="block_timestamp,asc", limit=20))
        t20 = self.get(f"/v1/accounts/{a}/transactions/trc20", dict(only_confirmed="true", limit=200))
        if txs is None and t20 is None:
            return None
        funders, first = [], None
        for t in txs or []:
            ts = t.get("block_timestamp")
            if ts and (first is None or ts < first):
                first = ts
            try:
                c = t["raw_data"]["contract"][0]
                v = c["parameter"]["value"]
                if c["type"] == "TransferContract" and to_base58(v.get("to_address")) == a and int(v.get("amount") or 0) > 0:
                    f = to_base58(v.get("owner_address"))
                    if f and f not in funders:
                        funders.append(f)
            except (KeyError, IndexError, TypeError, ValueError):
                continue
        rows = []
        for x in t20 or []:
            ti = x.get("token_info") or {}
            rows.append((x.get("from"), x.get("to"), _stable_usd(ti.get("symbol"), x.get("value"), ti.get("decimals"))))
            if x.get("block_timestamp") and (first is None or x["block_timestamp"] < first):
                first = x["block_timestamp"]
        return _summary(a, funders[:5], rows, first // 1000 if first else None)

    def contract_name(self, a):
        """TRON contract name (/wallet/getcontract), None for accounts or failures."""
        try:
            from .tron import to_hex
            key = self.pool.next() if len(self.pool) else None
            r = http_json("POST", self.url + "/wallet/getcontract", json=dict(value=to_hex(a)),
                          headers={"TRON-PRO-API-KEY": key} if key else {}, interval=0.3 if key else 1.2, retries=2,
                          timeout=30, validate=lambda o: isinstance(o, dict))
            self.calls += 1
            return r.get("name") or None
        except Exception as e:  # noqa: BLE001 - best effort
            log.debug("trongrid getcontract: %s", redact(e))
            return None


def _stable_usd(symbol, value, decimals):
    if str(symbol or "").upper() not in STABLES:
        return 0.0
    try:
        return int(value) / 10 ** int(decimals or 6)
    except (TypeError, ValueError):
        return 0.0


def _summary(a, funders, transfers, created_at=None):
    """transfers: (from, to, stablecoin usd) of the address's last token transfers."""
    outs = [(to, u) for frm, to, u in transfers if frm == a]
    ins = [frm for frm, to, _ in transfers if to == a]
    return dict(funders=funders, out_n=len(outs), out_sinks=len({t for t, _ in outs}), in_n=len(ins),
                in_senders=len(set(ins)), out_usd=round(sum(u for _, u in outs), 2), created_at=created_at)


def evm_history(es, chain, a):
    txl = es.call(chain, dict(module="account", action="txlist", address=a, sort="asc", page=1, offset=20))
    tok = es.call(chain, dict(module="account", action="tokentx", address=a, sort="desc", page=1, offset=200))
    if txl is None and tok is None:
        return None
    funders, first = [], None
    for t in txl or []:
        ts = int(t.get("timeStamp") or 0) or None
        if ts and (first is None or ts < first):
            first = ts
        f = (t.get("from") or "").lower()
        if (t.get("to") or "").lower() == a and int(t.get("value") or 0) > 0 and f not in funders:
            funders.append(f)
    rows = []
    for t in tok or []:
        ts = int(t.get("timeStamp") or 0) or None
        if ts and (first is None or ts < first):
            first = ts
        rows.append(((t.get("from") or "").lower(), (t.get("to") or "").lower(),
                     _stable_usd(t.get("tokenSymbol"), t.get("value"), t.get("tokenDecimal"))))
    return _summary(a, funders[:5], rows, first)


def evm_contract_name(es, chain, a):
    from .enrich import parse_source
    src = parse_source(es.call(chain, dict(module="contract", action="getsourcecode", address=a)))
    return src["name"] if src else None


def lookup_history(conn, es, rows, tg=None, now=None, time_box=FP_TIME_BOX):
    """Look up funders and token history of the largest uncapped generic-pull subjects, their largest victims and main
    recipient (cached in addr_history, re-checked after FP_RECHECK_SEC). Returns the number of addresses looked up."""
    now = now or now_ts()
    ensure_schema(conn)
    fresh = {(r["chain"], r["address"]) for r in conn.execute("SELECT chain,address FROM addr_history WHERE checked_at>=?",
                                                              (now - FP_RECHECK_SEC,))}
    cands = sorted((r for r in rows if r["tier"] in ("T1", "T2") and not set(r["labels"]) & KIT_KEEP
                    and (r.get("usd") or 0) >= FP_CHECK_MIN_USD), key=lambda r: -(r.get("usd") or 0))[:FP_MAX_SUBJECTS]
    todo, recipients = [], set()
    for r in cands:
        ch = r["chain"]
        vs = conn.execute("SELECT victim,SUM(usd) u FROM drains WHERE chain=? AND drainer=? GROUP BY victim ORDER BY u DESC "
                          "LIMIT ?", (ch, r["address"], FP_VICTIMS_PER_SUBJECT)).fetchall()
        rc = [x["recipient"] for x in conn.execute(
            "SELECT recipient,SUM(usd) u FROM drains WHERE chain=? AND drainer=? AND recipient IS NOT NULL "
            "GROUP BY recipient ORDER BY u DESC LIMIT ?", (ch, r["address"], FP_RECIPIENTS))]
        recipients |= {(ch, x) for x in rc}
        for a in [r["address"]] + rc + [v["victim"] for v in vs]:
            if a and (ch, a) not in fresh:
                todo.append((ch, a))
    tg = tg or TronGrid()
    t0, n = time.monotonic(), 0
    for ch, a in dict.fromkeys(todo):
        if time.monotonic() - t0 > time_box:
            break
        if ch == "tron":
            h = tg.history(a)
        elif es is not None and es.enabled:
            h = evm_history(es, ch, a)
        else:
            continue
        if h is None:
            continue
        name = None
        if (ch, a) in recipients:                       # DEX pool check: verified / deployed contract name
            name = tg.contract_name(a) if ch == "tron" else (evm_contract_name(es, ch, a) if es is not None else None)
        conn.execute("INSERT OR REPLACE INTO addr_history(chain,address,funders,out_n,out_sinks,in_n,checked_at,in_senders,"
                     "out_usd,created_at,contract_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (ch, a, json.dumps(h["funders"]), h["out_n"], h["out_sinks"], h["in_n"], now, h.get("in_senders"),
                      h.get("out_usd"), h.get("created_at"), name))
        n += 1
    conn.commit()
    return n


# ---------- enrichment: Arkham Intel ----------
def _norm(chain, a):
    return a if chain == "tron" else (a or "").lower()


def parse_arkham(x):
    """One BatchAddressResponse entry -> cache row dict (confirmed arkhamEntity only, never predictedEntity)."""
    e = x.get("arkhamEntity") or {}
    lb = x.get("arkhamLabel") or {}
    return dict(entity=e.get("name"), entity_id=e.get("id"), entity_type=e.get("type"),
                service=None if e.get("service") is None else bool(e.get("service")),
                label=lb.get("name"), deposit_service=x.get("depositServiceID") or None)


def arkham_batch(chain, addrs, key):
    """POST /intelligence/address/batch for one chain. Returns {address: entry} or None on failure (never logs the key)."""
    try:
        r = http_json("POST", ARKHAM_API + "/intelligence/address/batch", params=dict(chain=ARKHAM_CHAINS[chain]),
                      json=dict(addresses=list(addrs)), headers={"API-Key": key}, interval=1.1, retries=4, timeout=60,
                      validate=lambda o: isinstance(o, dict) and isinstance(o.get("addresses"), dict))
    except Exception as e:  # noqa: BLE001 - best effort
        log.warning("arkham %s: %s", chain, redact(e))
        return None
    return {_norm(chain, k): v for k, v in r["addresses"].items() if isinstance(v, dict)}


def lookup_arkham(conn, rows, now=None, batch=arkham_batch):
    """Arkham attribution (env ARKHAM_API_KEY) of the largest uncapped T1/T2 subjects without kit evidence: the subject,
    its main recipients and largest victims, one batch call per chain, cached ARKHAM_RECHECK_SEC (unattributed
    addresses too, so they are not looked up again). Returns the number of addresses looked up."""
    key = env("ARKHAM_API_KEY")
    if not key:
        return 0
    now = now or now_ts()
    conn.execute(ARKHAM_SCHEMA)
    fresh = {(r["chain"], r["address"]) for r in conn.execute("SELECT chain,address FROM arkham_cache WHERE checked_at>=?",
                                                              (now - ARKHAM_RECHECK_SEC,))}
    cands = sorted((r for r in rows if r["tier"] in ("T1", "T2") and r["chain"] in ARKHAM_CHAINS
                    and not set(r["labels"]) & KIT_KEEP and (r.get("usd") or 0) >= ARKHAM_MIN_USD),
                   key=lambda r: -(r.get("usd") or 0))[:ARKHAM_MAX_SUBJECTS]
    todo = defaultdict(list)
    for r in cands:
        ch = r["chain"]
        vs = [x["victim"] for x in conn.execute(
            "SELECT victim,SUM(usd) u FROM drains WHERE chain=? AND drainer=? GROUP BY victim ORDER BY u DESC LIMIT ?",
            (ch, r["address"], ARKHAM_VICTIMS))]
        rc = [x["recipient"] for x in conn.execute(
            "SELECT recipient,SUM(usd) u FROM drains WHERE chain=? AND drainer=? AND recipient IS NOT NULL GROUP BY recipient "
            "ORDER BY u DESC LIMIT ?", (ch, r["address"], ARKHAM_RECIPIENTS))]
        for a in [r["address"]] + rc + vs:
            if a and (ch, a) not in fresh and a not in todo[ch]:
                todo[ch].append(a)
    n = 0
    for ch, addrs in todo.items():
        for i in range(0, len(addrs), 1000):
            part = addrs[i:i + 1000]
            got = batch(ch, part, key)
            if got is None:
                continue
            for a in part:
                x = parse_arkham(got[_norm(ch, a)]) if _norm(ch, a) in got else dict(
                    entity=None, entity_id=None, entity_type=None, service=None, label=None, deposit_service=None)
                conn.execute("INSERT OR REPLACE INTO arkham_cache(chain,address,entity,entity_id,entity_type,service,label,"
                             "deposit_service,checked_at) VALUES(?,?,?,?,?,?,?,?,?)",
                             (ch, a, x["entity"], x["entity_id"], x["entity_type"],
                              None if x["service"] is None else int(x["service"]), x["label"], x["deposit_service"], now))
                n += 1
    conn.commit()
    return n


def arkham_for_contracts(conn, contracts):
    """Attach `arkham` (subject, payout wallets, largest victims with a cached attribution) to data.json contracts."""
    ark = load_arkham(conn)
    if not ark:
        return
    for c in contracts:
        ch = c["chain"]
        roles = [(c["address"], "subject")] + [(p["wallet"], p.get("role") or "payout") for p in c.get("payouts") or []]
        roles += [(x["victim"], "victim") for x in conn.execute(
            "SELECT victim,SUM(usd) u FROM drains WHERE chain=? AND drainer=? GROUP BY victim ORDER BY u DESC LIMIT ?",
            (ch, c["address"], ARKHAM_VICTIMS))]
        out, seen = [], set()
        for a, role in roles:
            x = ark.get((ch, a))
            if x and a not in seen:
                seen.add(a)
                out.append(dict(address=a, role=role, entity=x["entity"], entity_type=x["entity_type"], label=x["label"],
                                service=x["service"], deposit_service=x["deposit_service"]))
        if out:
            c["arkham"] = out
