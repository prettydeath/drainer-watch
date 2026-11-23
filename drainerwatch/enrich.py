"""Deployer + VASP links.

Labels come from the public wallet-attribution dataset. Everything here is passive: transfers already scanned, the
local db and best-effort Etherscan V2 calls. A deployer is never guessed: unresolved stays NULL / via='unknown'."""
import csv
import json
import io
import logging
import os
import re
from collections import defaultdict
from pathlib import Path

from .constants import (CHAINS, ETHERSCAN_V2, LABELS_REFRESH_SEC, SWEEP_WINDOW, VASP_CATEGORIES, WA_LOCAL_DEFAULT,
                        WA_RAW, ZERO)
from .db import meta_get, meta_set
from .tokens import fmt_amount
from .util import HttpError, http_json, http_text, iso, key_pool, looks_rate_limited, norm_addr, now_ts, redact

log = logging.getLogger("drainerwatch.enrich")

MAX_DEPLOYER_LOOKUPS = 50
MAX_BLOCK_SEARCH = 10          # keyless archive fallback, per chain per run
MAX_WALK_CALLS = 20
MAX_FLOWS_PER_CHUNK = 300


# ---------- labels ----------
def _wa_text(chain):
    name = CHAINS[chain]["wa"]
    local = os.environ.get("WA_DATA_DIR")
    if local and (Path(local) / f"{name}.csv").exists():
        return (Path(local) / f"{name}.csv").read_text(encoding="utf-8", errors="replace")
    try:
        return http_text(WA_RAW.format(name=name), timeout=120)
    except HttpError as e:
        fb = Path(WA_LOCAL_DEFAULT) / f"{name}.csv"
        if fb.exists():
            log.warning("labels %s: remote failed (%s); using local %s", chain, e, fb)
            return fb.read_text(encoding="utf-8", errors="replace")
        raise


def parse_labels(text, chain):
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        a = norm_addr(r.get("address"))
        cat = (r.get("category") or "").strip().lower()
        if not a or not cat:
            continue
        entity = (r.get("entity") or r.get("label") or "").strip()
        rows.append((chain, a, entity, (r.get("label") or "").strip(), cat))
    return rows


def refresh_labels(conn, chains=None, force=False):
    """Reload labels at most once per 24 h per chain. Failure keeps the previous labels."""
    now = now_ts()
    for chain in chains or CHAINS:
        if not force and now - int(meta_get(conn, f"labels_at:{chain}", "0") or 0) < LABELS_REFRESH_SEC:
            continue
        try:
            rows = parse_labels(_wa_text(chain), chain)
        except Exception as e:  # noqa: BLE001
            log.warning("labels %s: refresh failed: %s", chain, redact(e))
            continue
        conn.execute("DELETE FROM labels WHERE chain=?", (chain,))
        conn.executemany("INSERT OR REPLACE INTO labels(chain,address,entity,label,category) VALUES(?,?,?,?,?)", rows)
        meta_set(conn, f"labels_at:{chain}", now)
        conn.commit()
        log.info("labels %s: %d rows", chain, len(rows))


def load_labels(conn):
    return {(r["chain"], r["address"]): (r["entity"], r["category"], r["label"])
            for r in conn.execute("SELECT chain,address,entity,label,category FROM labels")}


def vasp_label(labels, chain, addr):
    """(entity, category) if addr is a VASP-class label, else None."""
    lb = labels.get((chain, addr))
    if lb and lb[1] in VASP_CATEGORIES:
        return lb[0], lb[1]
    return None


# ---------- subjects ----------
def load_subjects(conn, chain):
    """addr -> role for T1/T2 drainers, their payout wallets and resolved deployers (drainer wins over payout over deployer)."""
    subj = {}
    for r in conn.execute("SELECT address FROM contracts WHERE chain=? AND tier IN ('T1','T2')", (chain,)):
        subj[r["address"]] = "drainer"
    for r in conn.execute("SELECT p.wallet FROM payouts p JOIN contracts c ON c.chain=p.chain AND c.address=p.drainer "
                          "WHERE p.chain=? AND c.tier IN ('T1','T2')", (chain,)):
        subj.setdefault(r["wallet"], "payout")
    for r in conn.execute("SELECT d.deployer FROM contract_deployer d JOIN contracts c ON c.chain=d.chain AND "
                          "c.address=d.address WHERE d.chain=? AND d.deployer IS NOT NULL AND c.tier IN ('T1','T2')",
                          (chain,)):
        subj.setdefault(r["deployer"], "deployer")
    return subj


def add_link(conn, chain, subject, role, counterparty, kind, entity, category, tx, ts, amount=None, symbol=None,
             usd=None, confidence="high", tx_in=None):
    cur = conn.execute(
        "INSERT OR IGNORE INTO vasp_links(chain,subject,subject_role,counterparty,kind,entity,category,tx,tx_in,ts,"
        "amount,symbol,usd,confidence) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (chain, subject, role, counterparty, kind, entity, category, tx, tx_in, ts, amount, symbol, usd, confidence))
    return cur.rowcount > 0


def vasp_scan_chunk(ctx, transfers):
    """Direct links (subject -> labelled VASP wallet), candidate deposit addresses, and 72 h forward sweeps."""
    conn, chain, labels = ctx.conn, ctx.chain, ctx.labels
    ctx.subjects = load_subjects(conn, chain)
    subj = ctx.subjects
    if not subj and not conn.execute("SELECT 1 FROM flows WHERE chain=? LIMIT 1", (chain,)).fetchone():
        return
    pending = {}
    for r in conn.execute("SELECT subject,role,x,tx,block,ts FROM flows WHERE chain=?", (chain,)):
        pending.setdefault(r["x"], []).append(dict(r))
    hits_direct, new_flows, hits_sweep = [], [], []
    for t in transfers:
        v = vasp_label(labels, chain, t["to"]) if t["value"] > 0 else None
        if t["frm"] in subj and v:
            hits_direct.append((t, v))
        elif t["frm"] in subj and subj[t["frm"]] in ("drainer", "payout") and t["to"] != ZERO and t["value"] > 0 \
                and t["to"] not in subj and (chain, t["to"]) not in labels and not ctx.is_allowed(t["to"]) \
                and len(new_flows) < MAX_FLOWS_PER_CHUNK:
            new_flows.append(t)
        if v and t["frm"] in pending and t["frm"] not in subj:
            hits_sweep.append((t, v))
    if not (hits_direct or new_flows or hits_sweep):
        return
    blocks = {t["block"] for t, _ in hits_direct + hits_sweep} | {t["block"] for t in new_flows}
    ts = ctx.ts_of(sorted(blocks))
    ctx.tokens.ensure([t["token"] for t, _ in hits_direct + hits_sweep] + [t["token"] for t in new_flows])

    def fmt(t):
        sym, dec = ctx.tokens.get(t["token"])
        return fmt_amount(t["value"], dec), sym, ctx.prices.usd(chain, t["token"], t["value"], dec)

    for t, (ent, cat) in hits_direct:
        am, sym, usd = fmt(t)
        add_link(conn, chain, t["frm"], subj[t["frm"]], t["to"], "direct", ent, cat, t["tx"], ts.get(t["block"]), am,
                 sym, usd, "high")
        ctx.stats["links_direct"] += 1
    for t in new_flows:
        am, sym, usd = fmt(t)
        conn.execute("INSERT OR IGNORE INTO flows(chain,subject,role,x,tx,block,ts,token,amount,usd) "
                     "VALUES(?,?,?,?,?,?,?,?,?,?)", (chain, t["frm"], subj[t["frm"]], t["to"], t["tx"], t["block"],
                                                    ts.get(t["block"]), t["token"], am, usd))
        pending.setdefault(t["to"], []).append(dict(subject=t["frm"], role=subj[t["frm"]], x=t["to"], tx=t["tx"],
                                                    block=t["block"], ts=ts.get(t["block"])))
    for t, (ent, cat) in hits_sweep:
        am, sym, usd = fmt(t)
        tts = ts.get(t["block"])
        for f in pending.get(t["frm"], []):
            if f["block"] <= t["block"] and f["tx"] != t["tx"] and (
                    tts is None or f["ts"] is None or 0 <= tts - f["ts"] <= SWEEP_WINDOW):
                add_link(conn, chain, f["subject"], f["role"], t["frm"], "deposit_sweep", ent, cat, t["tx"], tts, am,
                         sym, usd, "medium", tx_in=f["tx"])
                ctx.stats["links_sweep"] += 1
    conn.execute("DELETE FROM flows WHERE ts < ?", (now_ts() - 7 * 86400,))
    conn.commit()


def is_deposit_sweep(inflow_ts, outflow_ts, to_labelled, window=SWEEP_WINDOW):
    """Heuristic core: X received from a subject, then forwarded to an exchange-labelled wallet within 72 h."""
    return bool(to_labelled) and inflow_ts is not None and outflow_ts is not None and 0 <= outflow_ts - inflow_ts <= window


# ---------- Etherscan V2 (best effort) ----------
MAX_XCHAIN_CODES = 40


def cross_chain_check(conn, rpcs=None, cap=MAX_XCHAIN_CODES):
    """K14 / S6: for T1/T2 contracts, eth_getCode of the same address on the other configured chains (<= cap per run;
    a (chain, address) already in `codes` is not fetched again). Same opcode skeleton -> `cross_chain` evidence on both
    sides (detail: linked chain and its tier). Returns the number of links."""
    from . import bytecode
    from .constants import CHAINS
    from .db import add_evidence
    from .rpc import Rpc
    have = {(r["chain"], r["address"]) for r in conn.execute("SELECT chain,address FROM codes")}
    src = [r for r in conn.execute("SELECT c.chain,c.address,c.tier,k.skeleton FROM contracts c JOIN codes k ON "
                                   "k.chain=c.chain AND k.address=c.address WHERE c.tier IN ('T1','T2') AND "
                                   "k.skeleton IS NOT NULL AND k.size>=100")]
    todo = defaultdict(list)
    n = 0
    for r in src:
        for ch in CHAINS:
            if ch != r["chain"] and (ch, r["address"]) not in have and n < cap:
                todo[ch].append(r)
                n += 1
    links, now = 0, now_ts()
    for ch, rows in todo.items():
        rpc = (rpcs or {}).get(ch) or Rpc(ch)
        try:
            codes = rpc.get_code_many([r["address"] for r in rows])
        except Exception as e:  # noqa: BLE001 - best effort
            log.warning("cross-chain check %s failed: %s", ch, redact(e))
            continue
        for r in rows:
            c = codes.get(r["address"])
            if c is None:
                continue
            info = bytecode.analyze(c)
            conn.execute("INSERT OR REPLACE INTO codes(chain,address,code_hash,size,skeleton,selectors) VALUES(?,?,?,?,?,?)",
                         (ch, r["address"], info["code_hash"], info["size"], info["skeleton"], json.dumps(info["selectors"])))
            if info["skeleton"] and info["skeleton"] == r["skeleton"]:
                add_evidence(conn, ch, r["address"], "cross_chain", f"xchain:{r['chain']}:{r['address']}", None, now,
                             dict(linked_chain=r["chain"], linked_tier=r["tier"], skeleton=r["skeleton"]))
                add_evidence(conn, r["chain"], r["address"], "cross_chain", f"xchain:{ch}:{r['address']}", None, now,
                             dict(linked_chain=ch, linked_tier=None, skeleton=r["skeleton"]))
                links += 1
    conn.commit()
    return links


class Etherscan:
    def __init__(self, calls_cap=200):
        self.pool = key_pool("ETHERSCAN_API_KEYS")
        self.unsupported = set()
        self.calls = 0
        self.cap = calls_cap

    @property
    def enabled(self):
        return len(self.pool) > 0

    def call(self, chain, params):
        """Returns the `result` list, [] for 'no records', or None on any failure (never raises, never logs keys)."""
        if not self.enabled or chain in self.unsupported or self.calls >= self.cap:
            return None
        for _ in range(min(3, len(self.pool))):
            key = self.pool.next()
            self.calls += 1
            try:
                r = http_json("GET", ETHERSCAN_V2, params=dict(params, chainid=CHAINS[chain]["id"], apikey=key),
                              interval=0.25, retries=2, timeout=40, validate=lambda o: isinstance(o, dict))
            except Exception as e:  # noqa: BLE001
                log.debug("etherscan %s: %s", chain, redact(e))
                return None
            res = r.get("result")
            if str(r.get("status")) == "1" and isinstance(res, list):
                return res
            text = f"{r.get('message')} {res}" if not isinstance(res, list) else str(r.get("message"))
            if isinstance(res, list) or "no transactions found" in text.lower() or "no records" in text.lower():
                return []
            if "not supported" in text.lower() or "upgrade" in text.lower() or "free api access" in text.lower():
                self.unsupported.add(chain)
                log.info("etherscan: %s not covered by this plan", chain)
                return None
            if looks_rate_limited(text):
                self.pool.mark_bad(key)
                continue
            log.debug("etherscan %s %s: %s", chain, params.get("action"), redact(text[:120]))
            return None
        return None


def pick_funder(deployer, normal, internal):
    """Earliest incoming native transfer to `deployer` (value>0, successful) among normal and internal txs."""
    best = None
    for rows in (normal or [], internal or []):
        for r in rows:
            try:
                if (r.get("to") or "").lower() != deployer or int(r.get("value") or 0) <= 0 or r.get("isError") == "1":
                    continue
                ts = int(r.get("timeStamp"))
            except (TypeError, ValueError):
                continue
            frm = norm_addr(r.get("from"))
            if frm and frm != deployer and (best is None or ts < best[2]):
                best = (frm, r.get("hash") or r.get("transactionHash"), ts)
    return best


class NoArchive(RuntimeError):
    """The node refuses historical state (eth_getCode at an old block)."""


def find_creation_block(rpc, addr):
    """First block where `addr` has code (binary search over eth_getCode at historical blocks). Returns None if the
    address has no code now; raises NoArchive if the node cannot serve historical state."""
    def has(b):
        try:
            c = rpc.call("eth_getCode", [addr, hex(b)], retries=2)
        except HttpError as e:
            raise NoArchive(redact(e)) from e
        return c not in ("0x", "", None)

    head = rpc.block_number()
    has(max(1, head // 2))                    # probe: a non-archive node errors out here
    if not has(head):
        return None
    lo, hi = 0, head
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if has(mid):
            hi = mid
        else:
            lo = mid
    return hi


def creation_from_block(rpc, addr, block):
    """(creator_tx_hash, tx.from) if `addr` was created by a top-level tx in `block` (receipt.contractAddress), else
    (None, None): an internal (factory/CREATE2) creation, whose creator is not visible without traces."""
    try:
        rcs = rpc.call("eth_getBlockReceipts", [hex(block)], retries=2) or []
    except HttpError:
        return None, None
    for r in rcs:
        if (r.get("contractAddress") or "").lower() == addr:
            return r.get("transactionHash"), (r.get("from") or "").lower() or None
    return None, None


def resolve_deployers(conn, es, rpcs, labels, budget=MAX_DEPLOYER_LOOKUPS):
    """Deployer for every T1/T2 contract (<= budget lookups per run). 1) creations table, 2) Etherscan
    getcontractcreation (+ tx.from from RPC), 3) unknown. Then the deployer's funder and a funding link."""
    now = now_ts()
    todo = conn.execute(
        "SELECT c.chain,c.address FROM contracts c LEFT JOIN contract_deployer d ON d.chain=c.chain AND "
        "d.address=c.address WHERE c.tier IN ('T1','T2') AND (d.address IS NULL OR (d.via='unknown' AND d.resolved_at<?)) "
        "ORDER BY c.tier, c.last_seen DESC LIMIT ?", (now - 86400, budget)).fetchall()
    searches = {}
    for r in todo:
        chain, addr = r["chain"], r["address"]
        cr = conn.execute("SELECT deployer,tx FROM creations WHERE chain=? AND address=?", (chain, addr)).fetchone()
        dep = tx = factory = block = None
        via = "unknown"
        if cr:
            dep, tx, via = cr["deployer"], cr["tx"], "toplevel"
        else:
            res = es.call(chain, dict(module="contract", action="getcontractcreation", contractaddresses=addr))
            if res:
                row = res[0]
                creator, tx = norm_addr(row.get("contractCreator")), row.get("txHash")
                dep = creator
                fac = norm_addr(row.get("contractFactory"))
                if tx and chain in rpcs:
                    try:
                        t = rpcs[chain].txs_by_hash([tx]).get(tx)
                    except Exception:  # noqa: BLE001
                        t = None
                    if t:
                        dep = t["from"].lower()
                        if creator and creator != dep:
                            factory = creator
                if not factory and fac and fac != dep:
                    factory = fac
                if dep:
                    via = "etherscan"
        if via == "unknown" and not cr and chain in rpcs and searches.get(chain, 0) < MAX_BLOCK_SEARCH \
                and not getattr(rpcs[chain], "no_archive", False):
            searches[chain] = searches.get(chain, 0) + 1
            try:
                block = find_creation_block(rpcs[chain], addr)
            except NoArchive as e:
                rpcs[chain].no_archive = True
                log.info("deployer block-search %s: node has no archive state (%s); skipping", chain, e)
            except Exception as e:  # noqa: BLE001
                log.debug("block-search %s: %s", chain, redact(e))
            if block:
                tx, dep = creation_from_block(rpcs[chain], addr, block)
                via = "block-search"      # internal creation: only the block is known, creator/factory stay unknown
        conn.execute("INSERT OR REPLACE INTO contract_deployer(chain,address,deployer,tx,via,factory,resolved_at,block) "
                     "VALUES(?,?,?,?,?,?,?,?)", (chain, addr, dep, tx, via, factory, now, block))
    conn.commit()
    # funders
    deps = conn.execute(
        "SELECT DISTINCT d.chain,d.deployer FROM contract_deployer d LEFT JOIN deployer_info i ON i.chain=d.chain AND "
        "i.address=d.deployer WHERE d.deployer IS NOT NULL AND (i.address IS NULL OR (i.funder IS NULL AND i.resolved_at<?)) "
        "LIMIT ?", (now - 86400, budget)).fetchall()
    for r in deps:
        chain, dep = r["chain"], r["deployer"]
        base = dict(address=dep, startblock=0, endblock=99999999, page=1, offset=5, sort="asc")
        normal = es.call(chain, dict(base, module="account", action="txlist"))
        internal = es.call(chain, dict(base, module="account", action="txlistinternal")) if normal is not None else None
        if normal is None and internal is None:
            continue    # API unavailable: retry on a later run
        f = pick_funder(dep, normal, internal)
        conn.execute("INSERT OR REPLACE INTO deployer_info(chain,address,funder,funder_tx,funder_ts,resolved_at) "
                     "VALUES(?,?,?,?,?,?)", (chain, dep, f[0] if f else None, f[1] if f else None,
                                            f[2] if f else None, now))
        v = vasp_label(labels, chain, f[0]) if f else None
        if f and v:
            add_link(conn, chain, dep, "deployer", f[0], "funding", v[0], v[1], f[1], f[2], confidence="high")
    conn.commit()


def walk_payouts(conn, es, labels, prices, budget=MAX_WALK_CALLS):
    """Optional 1-2 hop forward walk for T1 payout wallets through Etherscan tokentx (<= budget calls per run).
    hop 1: wallet -> labelled VASP = direct link; hop 2: the two busiest non-labelled recipients, forwarding to a VASP
    wallet within 72 h = deposit_sweep (medium)."""
    if not es.enabled:
        return 0
    used = 0
    now = now_ts()
    rows = conn.execute("SELECT DISTINCT p.chain,p.wallet FROM payouts p JOIN contracts c ON c.chain=p.chain AND "
                        "c.address=p.drainer WHERE c.tier='T1' ORDER BY c.usd DESC LIMIT 60").fetchall()

    def tokentx(chain, addr):
        nonlocal used
        used += 1
        return es.call(chain, dict(module="account", action="tokentx", address=addr, page=1, offset=100, sort="desc",
                                   startblock=0, endblock=99999999)) or []

    def rec(chain, subject, role, cp, kind, v, row, tx_in=None, conf="high"):
        dec = int(row.get("tokenDecimal") or 0) if str(row.get("tokenDecimal") or "").isdigit() else None
        raw = int(row.get("value") or 0)
        add_link(conn, chain, subject, role, cp, kind, v[0], v[1], row.get("hash"), int(row.get("timeStamp") or 0),
                 fmt_amount(raw, dec), row.get("tokenSymbol"), prices.usd(chain, (row.get("contractAddress") or "").lower(),
                                                                          raw, dec), conf, tx_in=tx_in)

    for r in rows:
        chain, w = r["chain"], r["wallet"]
        key = f"walked:{chain}:{w}"
        if used >= budget or chain in es.unsupported or now - int(meta_get(conn, key, "0") or 0) < 86400:
            continue
        txs = [t for t in tokentx(chain, w) if (t.get("from") or "").lower() == w]
        meta_set(conn, key, now)
        busiest = {}
        for t in txs:
            to = (t.get("to") or "").lower()
            v = vasp_label(labels, chain, to)
            if v:
                rec(chain, w, "payout", to, "direct", v, t)
            elif to and to != w and (chain, to) not in labels:
                busiest.setdefault(to, []).append(t)
        for x, ins in sorted(busiest.items(), key=lambda kv: -len(kv[1]))[:2]:
            if used >= budget:
                break
            first_in = min(int(t.get("timeStamp") or 0) for t in ins)
            for t2 in tokentx(chain, x):
                to2 = (t2.get("to") or "").lower()
                v = vasp_label(labels, chain, to2)
                if v and (t2.get("from") or "").lower() == x and is_deposit_sweep(first_in, int(t2.get("timeStamp") or 0), True):
                    rec(chain, w, "payout", x, "deposit_sweep", v, t2, tx_in=ins[-1].get("hash"), conf="medium")
                    break
        conn.commit()
    return used
