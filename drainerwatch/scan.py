"""Per-chain ingestion: cursor, adaptive getLogs chunks, detectors D1-D4, ETH full-block pass (D5-D7)."""
import json
import logging
import time
from collections import Counter, defaultdict

from . import bytecode, detectors, enrich
from .auth7702 import authority_of
from .constants import (ALLOWLIST, ALLOWLIST_CSV, APPROVAL_KEEP_SEC, BAIT_CAPTURE, MALICIOUS_CATEGORIES, CHAINS,
                        CONFIRMATIONS, D8_MAX_LOOKUPS, D8_MAX_SPENDER_NONCE, D8_MIN_VICTIM_NONCE, GEN_BACK_WINDOW,
                        GEN_FRESH_SEC, GEN_MAX_USES, INITIAL_BLOCKS, KIT_APPROVAL_AMOUNTS, KIT_DEPOSIT_GAS,
                        KIT_DEPOSIT_MAX_NONCE, KIT_DEPOSIT_MIN_SHARE, MIN_USD, MS_NEW_SELECTORS, MS_WITHDRAW_SELECTORS,
                        ONESHOT_FUND_WINDOW, ONESHOT_KEEP, ONESHOT_MAX_NONCE, ONESHOT_RETURN_GAS, ONESHOT_RETURN_WINDOW,
                        PERMIT2, PERMIT_SELECTORS, REDFLAG_SELECTORS, SEL_MS_NEW_DEPOSIT, SEL_MULTICALL_DEADLINE,
                        SEL_P2_TRANSFER_FROM, SEL_P2_TRANSFER_FROM_BATCH, SEL_R02_EXACT_INPUT_SINGLE, SEL_TRANSFER_FROM,
                        SEL_V3_EXACT_INPUT_SINGLE, SWAP_V2_SELECTORS, XSPLIT_MAX_GAP, ZERO)
from .db import add_evidence, meta_get, meta_set
from .seeds import load_allowlist
from .rpc import Rpc, parse_logs
from .tokens import Tokens, fmt_amount
from .util import env, hx, iso, now_ts

log = logging.getLogger("drainerwatch.scan")

MAX_TX_LOOKUPS = 400
MAX_CODE_LOOKUPS = 600
MAX_SEED_CODES = 100
MAX_CREATIONS = 400
MAX_AUTH_RECOVER = 300
MAX_DELEGATE_CODES = 40


class Ctx:
    """Everything a chunk needs. Small enough to fake in tests."""

    def __init__(self, conn, chain, rpc, seeds, labels, prices, deadline=None, code_cache=None, family_index=None):
        self.conn, self.chain, self.rpc = conn, chain, rpc
        self.seeds, self.labels, self.prices = seeds, labels, prices
        self.deadline = deadline or (time.monotonic() + 3600)
        self.tokens = Tokens(conn, rpc, chain)
        self.allow = set(ALLOWLIST) | load_allowlist(chain)
        self.txs: dict = {}
        self.code_hex: dict = code_cache if code_cache is not None else {}
        self.full_txs = False
        self.nonce: dict = {}             # D8: addr -> tx count at latest             # receipts source: from/to of every tx in the chunk is known
        self.stats = Counter()
        self.pev, self.pdr = [], []       # pending evidence / drains
        self.owner_spenders: dict = defaultdict(set)
        self.known_spenders: set = set()
        self.payout_wallets: set = set()
        self.strong_wallets: set = set()
        self.seed_index = None
        self.fixed_family = family_index  # backtest: family library fixed by the caller (seeds may be disabled)
        self.subjects: dict = {}
        self.pending_x: dict = {}
        self.xs_carry: list = []          # R-A1: pull legs of the last blocks of the previous chunk
        self.xs_batch: set = set()        # R-A1: txs moving tokens of >= 3 owners (batch relayers), never a split leg
        self.bait_set = None              # D7: contracts known as bait (bait_payable evidence / ms_drainer kit code)
        self.chunk_tr, self.chunk_ap = [], []   # parsed logs of the current chunk (the ETH block pass reuses them)
        self.k5_pulls: dict = defaultdict(list)  # K5: worker -> pending pulls (nonce <= 3, value really moved)
        self.plain: list = []             # K5/K12/K2: recent plain native transfers (from, to, tx, block, gas, value)
        self.gen_created: dict = {}       # K2: generated bait contract -> (creation block, deployer)
        self.kit_info: dict = {}          # address -> bytecode.analyze() result (cache)
        self.gen_receivers: dict = {}     # K2: generated bait -> receivers read from storage

    # ---- predicates ----
    def is_allowed(self, addr):
        if addr in self.allow:
            return True
        lb = self.labels.get((self.chain, addr))
        return bool(lb and lb[1] not in MALICIOUS_CATEGORIES)   # any non-malicious label = legitimate subject

    def is_delegated(self, addr):
        return bytecode.is_delegated_eoa(self.code_hex.get(addr))

    def is_contract(self, addr):
        c = self.code_hex.get(addr)
        return bool(c) and c != "0x" and not bytecode.is_delegated_eoa(c)

    # ---- lookups ----
    def lookup_txs(self, hashes, cap=MAX_TX_LOOKUPS):
        need = [h for h in dict.fromkeys(hashes) if h not in self.txs][:cap]
        if need:
            self.stats["tx_lookups"] += len(need)
            for h, t in self.rpc.txs_by_hash(need).items():
                self.txs[h] = {"from": t["from"].lower(), "to": (t.get("to") or "").lower() or None,
                               "block": hx(t.get("blockNumber")), "input": t.get("input", "0x"),
                               "value": hx(t.get("value"))}

    def ensure_codes(self, addrs, cap=MAX_CODE_LOOKUPS):
        need = [a for a in dict.fromkeys(addrs) if a not in self.code_hex][:cap]
        if need:
            self.stats["code_lookups"] += len(need)
            for a, c in self.rpc.get_code_many(need).items():
                if c is not None:
                    self.code_hex[a] = c

    def analysis(self, addr):
        """Cached bytecode analysis of a contract whose code is known (None for EOAs / unknown code)."""
        if addr not in self.kit_info:
            c = self.code_hex.get(addr)
            if c is None:
                return None
            self.kit_info[addr] = bytecode.analyze(c) if self.is_contract(addr) else None
        return self.kit_info[addr]

    def ts_of(self, blocks):
        return self.rpc.block_times(list(blocks))

    # ---- emit ----
    def emit(self, type_, address, tx, block, detail):
        self.pev.append(dict(type=type_, address=address, tx=tx, block=block, detail=detail))

    def flush(self):
        blocks = {e["block"] for e in self.pev} | {d["block"] for d in self.pdr}
        ts = self.ts_of(sorted(b for b in blocks if b)) if blocks else {}
        now = now_ts()
        for e in self.pev:
            if add_evidence(self.conn, self.chain, e["address"], e["type"], e["tx"], e["block"],
                            ts.get(e["block"]) or now, e["detail"]):
                self.stats["ev_" + e["type"]] += 1
        for d in self.pdr:
            self.conn.execute(
                "INSERT OR IGNORE INTO drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,"
                "recipient) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.chain, d["tx"], d["li"], ts.get(d["block"]) or now, d["victim"], d["drainer"], d["token"],
                 d["symbol"], d["decimals"], d["amount"], d["usd"], d["recipient"]))
        self.pev, self.pdr = [], []
        self.conn.commit()

    def drain_row(self, leg, victim, drainer):
        sym, dec = self.tokens.get(leg["token"])
        return dict(tx=leg["tx"], li=leg["li"], block=leg["block"], victim=victim, drainer=drainer,
                    token=leg["token"], symbol=sym, decimals=dec, amount=fmt_amount(leg["value"], dec),
                    usd=self.prices.usd(self.chain, leg["token"], leg["value"], dec), recipient=leg["to"])

    # ---- bytecode (D5) ----
    def seed_family_index(self):
        if self.fixed_family is not None:
            return self.fixed_family
        if self.seed_index is None:
            idx = []
            for r in self.conn.execute(
                    "SELECT c.address,c.skeleton,c.selectors,c.size FROM codes c WHERE c.skeleton IS NOT NULL"):
                if self.seeds.by_addr.get(r["address"]):
                    idx.append(dict(address=r["address"], skeleton=r["skeleton"],
                                    selectors=set(json.loads(r["selectors"] or "[]")), size=r["size"]))
            self.seed_index = idx
        return self.seed_index

    def persist_code(self, addr):
        """Analyse (once) and store skeleton/selectors. Returns analysis dict or None if code unknown."""
        c = self.code_hex.get(addr)
        if c is None:
            return None
        info = bytecode.analyze(c)
        if bytecode.is_delegated_eoa(c):
            return info
        self.conn.execute("INSERT OR REPLACE INTO codes(chain,address,code_hash,size,skeleton,selectors) "
                          "VALUES(?,?,?,?,?,?)", (self.chain, addr, info["code_hash"], info["size"], info["skeleton"],
                                                  json.dumps(info["selectors"])))
        if info["skeleton"] and self.seeds.by_addr.get(addr):
            self.seed_index = None
        return info

    def d5(self, addr, tx, block, extra=None):
        """Red-flag selectors and family match for one contract; emits `bytecode` evidence. Once per address."""
        if self.conn.execute("SELECT 1 FROM evidence WHERE chain=? AND address=? AND type='bytecode' LIMIT 1",
                             (self.chain, addr)).fetchone() or any(
                e["address"] == addr and e["type"] == "bytecode" for e in self.pev):
            return None
        info = self.persist_code(addr)
        if not info or not info["skeleton"]:
            return None
        found = {}
        if info["redflags"]:
            found["redflags"] = info["redflags"]
        if info.get("kit"):
            found["kit"] = info["kit"]
            if info["kit"] == "ms_drainer" and self.bait_set is not None:
                self.bait_set.add(addr)
        if info.get("owner_gated_puller"):
            found["owner_gated_puller"] = True
        if info.get("kit_exact"):
            found["kit_exact"] = info["kit_exact"]
        if info.get("ms_variant"):
            found["ms_variant"] = info["ms_variant"]
        m = bytecode.match_family(info["skeleton"], info["selectors"], info["size"], self.seed_family_index())
        if m:
            found.update(family=m[0], via=m[1], matched_seed=self.seed_family_index()[m[2]]["address"])
        if found:
            self.emit("bytecode", addr, tx, block, dict(found, **(extra or {}), size=info["size"]))
            return found
        return None

    def fetch_seed_codes(self, cap=MAX_SEED_CODES):
        """Lazily fetch bytecode of seed addresses on this chain (<= cap per run), cached incl. EOAs (size 0)."""
        have = {r["address"] for r in self.conn.execute("SELECT address FROM codes WHERE chain=?", (self.chain,))}
        todo = [a for a in self.seeds.addresses(self.chain) if a not in have][:cap]
        if not todo:
            return 0
        res = self.rpc.get_code_many(todo)
        for a, c in res.items():
            if c is None:
                continue
            self.code_hex[a] = c
            info = bytecode.analyze(c)
            self.conn.execute("INSERT OR REPLACE INTO codes(chain,address,code_hash,size,skeleton,selectors) "
                              "VALUES(?,?,?,?,?,?)", (self.chain, a, info["code_hash"], info["size"],
                                                      info["skeleton"], json.dumps(info["selectors"])))
        self.seed_index = None
        self.conn.commit()
        self.stats["seed_codes"] += len(todo)
        return len(todo)


# ---------- state loading ----------
def load_state(ctx):
    now = now_ts()
    ctx.conn.execute("DELETE FROM approvals WHERE ts < ?", (now - APPROVAL_KEEP_SEC,))
    for r in ctx.conn.execute("SELECT owner,spender FROM approvals WHERE chain=?", (ctx.chain,)):
        ctx.owner_spenders[r["owner"]].add(r["spender"])
    refresh_known(ctx)
    ctx.subjects = enrich.load_subjects(ctx.conn, ctx.chain)


def refresh_known(ctx):
    conn, chain = ctx.conn, ctx.chain
    ctx.known_spenders = {r["address"] for r in conn.execute("SELECT address FROM contracts WHERE chain=?", (chain,))}
    ctx.known_spenders |= {r["drainer"] for r in conn.execute("SELECT DISTINCT drainer FROM payouts WHERE chain=?",
                                                              (chain,))}
    # split payouts only: customer (MS bait) / collector (D8 recipient) wallets do not feed D3/D4 candidate generation
    ctx.payout_wallets = {r["wallet"] for r in conn.execute(
        "SELECT DISTINCT wallet FROM payouts WHERE chain=? AND role IN ('affiliate','operator')", (chain,))}
    ctx.payout_wallets |= set(ctx.seeds.addresses(chain))
    # strong operator wallets: seeds, and payout wallets of T1 contracts that are EOAs (no code)
    t1 = [r["wallet"] for r in conn.execute("SELECT DISTINCT p.wallet FROM payouts p JOIN contracts c ON c.chain=p.chain "
                                            "AND c.address=p.drainer WHERE p.chain=? AND c.tier='T1' AND p.role IN ('affiliate','operator')", (chain,))]
    t1 = [w for w in t1 if not ctx.is_allowed(w)]
    if t1:
        ctx.ensure_codes(t1, cap=100)
    ctx.strong_wallets = set(ctx.seeds.addresses(chain)) | {w for w in t1 if w in ctx.code_hex and not ctx.is_contract(w)}


def update_payouts(conn, chain, drainer, recipients):
    for r in recipients:
        row = conn.execute("SELECT share,txs,role FROM payouts WHERE chain=? AND drainer=? AND wallet=?",
                           (chain, drainer, r["wallet"])).fetchone()
        if row and row["role"] not in ("affiliate", "operator"):     # was customer/collector: becomes a split payout
            conn.execute("UPDATE payouts SET share=?, txs=txs+1, role=? WHERE chain=? AND drainer=? AND wallet=?",
                         (r["share"], r["role"], chain, drainer, r["wallet"]))
        elif row:
            n = row["txs"] + 1
            conn.execute("UPDATE payouts SET share=?, txs=? WHERE chain=? AND drainer=? AND wallet=?",
                         ((row["share"] * row["txs"] + r["share"]) / n, n, chain, drainer, r["wallet"]))
        else:
            conn.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES(?,?,?,?,?,1)",
                         (chain, drainer, r["wallet"], r["role"], r["share"]))
    rows = conn.execute("SELECT wallet,share FROM payouts WHERE chain=? AND drainer=? AND role IN ('affiliate','operator') "
                        "ORDER BY share DESC", (chain, drainer)).fetchall()
    for i, row in enumerate(rows):
        conn.execute("UPDATE payouts SET role=? WHERE chain=? AND drainer=? AND wallet=?",
                     ("affiliate" if i == 0 else "operator", chain, drainer, row["wallet"]))


def store_approvals(ctx, approvals, ts):
    """Keep ERC-20 approvals only for spenders worth tracking (seed / known drainer / >=3 distinct owners in the chunk),
    never allowlisted ones: storing every approval would be millions of rows."""
    owners = defaultdict(set)
    for a in approvals:
        if a["kind"] == "approval" and a["value"] > 0:
            owners[a["spender"]].add(a["owner"])
    n = 0
    for a in approvals:
        if a["kind"] != "approval" or a["value"] == 0 or ctx.is_allowed(a["spender"]) or a["spender"] == ZERO:
            continue
        sp = a["spender"]
        if sp in ctx.known_spenders or ctx.seeds.has(ctx.chain, sp) or len(owners[sp]) >= 3:
            ctx.conn.execute("INSERT OR IGNORE INTO approvals(chain,owner,spender,token,tx,block,ts) VALUES(?,?,?,?,?,?,?)",
                             (ctx.chain, a["owner"], sp, a["token"], a["tx"], a["block"], ts))
            ctx.owner_spenders[a["owner"]].add(sp)
            n += 1
            if n >= 5000:
                break
    ctx.stats["approvals_kept"] += n


# ---------- chunk processing ----------
def process_chunk(ctx, a, b, logs, txmeta=None):
    """Detect on one block range of parsed Transfer/Approval logs. txmeta (receipts source): from/to of every tx."""
    if txmeta is not None:
        ctx.txs.update(txmeta)
        ctx.full_txs = True
    tr, ap = parse_logs(logs)
    ctx.chunk_tr, ctx.chunk_ap = tr, ap
    ctx.stats["logs"] += len(logs)
    ctx.stats["transfers"] += len(tr)
    ctx.stats["approvals"] += len(ap)
    chain = ctx.chain
    cts = ctx.ts_of([b]).get(b) or now_ts()
    store_approvals(ctx, ap, cts)

    # D1
    ev1, legs1 = detectors.d1_seed_activity(chain, tr, ap, ctx.seeds)
    for e in ev1:
        ctx.emit(e["type"], e["address"], e["tx"], e["block"], e["detail"])
    if legs1:
        ctx.tokens.ensure([t["token"] for t in legs1])
        for t in legs1:
            ctx.pdr.append(ctx.drain_row(t, t["frm"], t["to"]))

    # D9 approval_fingerprint: kit-hard-coded approval amount (all chains, both sources)
    for c in detectors.d9_candidates(ap, ctx.is_allowed):
        ctx.emit("approval_fingerprint", c["spender"], c["tx"], c["block"],
                 dict(victim=c["owner"], token=c["token"], kit=c["kit"]))
        ctx.stats["d9_confirmed"] += 1

    # candidates
    c2 = detectors.d2_candidates(tr, ctx.is_allowed)
    exclude = {(c["tx"], c["victim"]) for c in c2}
    c3 = detectors.d3_candidates(tr, ctx.owner_spenders, ctx.strong_wallets, exclude)
    c4 = detectors.d4_candidates(tr, ctx.payout_wallets | ctx.strong_wallets, ctx.is_allowed)
    ctx.stats["d2_candidates"] += len(c2)
    ctx.stats["d3_candidates"] += len(c3)
    ctx.stats["d4_candidates"] += len(c4)

    ctx.lookup_txs([c["tx"] for c in c2] + list(c3))
    want = []
    for c in c2:
        t = ctx.txs.get(c["tx"])
        if t and t["to"]:
            want += [t["to"], c["victim"]]
    for h, legs in c3.items():
        t = ctx.txs.get(h)
        if t and t["to"]:
            want += [t["to"]] + [x["frm"] for x in legs]
    want += [t["frm"] for t in c4]
    ctx.ensure_codes(want)
    ctx.tokens.ensure({c["token"] for c in c2} | {x["token"] for legs in c3.values() for x in legs})

    # D2
    confirmed = {}   # (drainer, tx) -> aggregated
    for c in c2:
        t = ctx.txs.get(c["tx"])
        if not t:
            continue
        if int(c["victim"], 16) <= 0xFFFF:
            continue                            # precompile-like 'victim'
        res = detectors.d2_confirm(c, t, ctx.is_contract, ctx.is_allowed, ctx.is_allowed)
        if not res:
            continue
        spoof = ctx.tokens.is_spoof(c["token"])   # fake lookalike token: address-poisoning pattern, T3 at most
        ctx.tokens.ensure([c["token"]])
        legs = c["legs"]
        usd = [ctx.prices.usd(chain, c["token"], x["value"], ctx.tokens.get(c["token"])[1]) for x in legs]
        if all(u is not None for u in usd) and sum(usd) < MIN_USD:
            continue
        k = (res["drainer"], c["tx"])
        agg = confirmed.setdefault(k, dict(block=c["block"], spoof=spoof, victims=[], token=c["token"], recipients=res["recipients"],
                                           legs=[]))
        agg["victims"].append(c["victim"])
        agg["legs"] += [(x, c["victim"]) for x in legs]
    for (drainer, tx), agg in confirmed.items():
        det = dict(victims=sorted(set(agg["victims"])), token=agg["token"], recipients=agg["recipients"])
        if agg["spoof"]:
            det["spoof"] = True               # no payouts / drains: nothing was really pulled
            ctx.emit("split_pull", drainer, tx, agg["block"], det)
            ctx.stats["d2_spoof"] += 1
            continue
        if add_evidence_pending(ctx, "split_pull", drainer, tx, agg["block"], det):
            update_payouts(ctx.conn, chain, drainer, agg["recipients"])
        for x, victim in agg["legs"]:
            ctx.pdr.append(ctx.drain_row(x, victim, drainer))
        ctx.d5(drainer, tx, agg["block"])
        ctx.stats["d2_confirmed"] += 1

    # D3
    for h, legs in c3.items():
        t = ctx.txs.get(h)
        if not t:
            continue
        legs = [x for x in legs if not ctx.tokens.is_spoof(x["token"]) and int(x["frm"], 16) > 0xFFFF]
        res = detectors.d3_confirm(legs, t, ctx.owner_spenders, ctx.strong_wallets, ctx.is_contract, ctx.is_allowed)
        if not res:
            continue
        ctx.tokens.ensure([x["token"] for x in res["legs"]])
        dr = [ctx.drain_row(x, x["frm"], res["drainer"]) for x in res["legs"]]
        if all(d["usd"] is not None for d in dr) and sum(d["usd"] for d in dr) < MIN_USD:
            continue
        ctx.emit("multi_victim_pull", res["drainer"], h, legs[0]["block"], dict(victims=res["victims"]))
        ctx.pdr += dr
        ctx.d5(res["drainer"], h, legs[0]["block"])
        ctx.stats["d3_confirmed"] += 1

    # D8 (receipts source only: needs tx.from/tx.to of every tx without per-tx lookups)
    if ctx.full_txs:
        c8 = [c for c in detectors.d8_candidates(tr, ctx.txs, ctx.is_allowed)
              if not ctx.tokens.is_spoof(c["token"]) and int(c["frm"], 16) > 0xFFFF]
        sp7702 = [c["spender"] for c in c8 if c["via"] == "7702"]
        if sp7702:     # keep only pulls whose tx.to is an EIP-7702-delegated EOA (cheap: one cached code lookup each)
            ctx.ensure_codes(sp7702, cap=D8_MAX_LOOKUPS * 3)
            c8 = [c for c in c8 if c["via"] != "7702" or ctx.is_delegated(c["spender"])]
        ctx.stats["d8_candidates"] += len(c8)
        if c8:
            ctx.ensure_codes([x for c in c8 for x in (c["frm"], c["to"], c["spender"])], cap=D8_MAX_LOOKUPS * 3)
            n0 = len(c8)
            c8 = [c for c in c8 if all(x in ctx.code_hex for x in (c["frm"], c["to"], c["spender"]))]  # unknown code: skip
            ctx.stats["d8_truncated"] += n0 - len(c8)
            need = list(dict.fromkeys(x for c in c8 for x in (c["frm"], c["spender"]) if x not in ctx.nonce))
            ctx.stats["d8_truncated"] += max(0, len(need) - D8_MAX_LOOKUPS)
            need = need[:D8_MAX_LOOKUPS]
            if need:
                ctx.stats["nonce_lookups"] += len(need)
                ctx.nonce.update(ctx.rpc.nonces(need))
            ctx.tokens.ensure({c["token"] for c in c8})
            for c in c8:
                if not detectors.d8_confirm(c, ctx.is_contract, ctx.nonce, ctx.is_delegated):
                    continue
                d = ctx.drain_row(c, c["frm"], c["spender"])
                if d["usd"] is not None and d["usd"] < MIN_USD:
                    continue
                if add_evidence_pending(ctx, "eoa_spender_pull", c["spender"], c["tx"], c["block"],
                                        dict(victim=c["frm"], recipient=c["to"], token=c["token"], via=c["via"])):
                    add_payout(ctx.conn, chain, c["spender"], c["to"], "collector")
                ctx.pdr.append(d)
                ctx.stats["d8_confirmed"] += 1

        # R-A1 cross-tx split (needs tx.from of every tx)
        xsplit(ctx, tr)
        # K9 owner-collector pulls (needs tx.from/to of every tx)
        owner_collect(ctx, tr)

    # D4
    for t in c4:
        if ctx.is_contract(t["frm"]):
            ctx.emit("pays_known_operator", t["frm"], t["tx"], t["block"], dict(wallet=t["to"], token=t["token"],
                                                                                strong=t["to"] in ctx.strong_wallets))
            ctx.d5(t["frm"], t["tx"], t["block"])

    ctx.flush()
    refresh_known(ctx)
    try:
        enrich.vasp_scan_chunk(ctx, tr)
    except Exception as e:  # noqa: BLE001 - the VASP pass is best effort
        log.warning("%s: vasp pass failed: %s", chain, e)


def xsplit(ctx, tr):
    """R-A1: same caller + victim + token, >= 2 pulls in different txs within XSPLIT_MAX_GAP s (same block or adjacent)
    to >= 2 recipients, largest share in [0.60, 0.99] (the TRON VerifyAccount family splits 98/2 in two txs).
    Legs of the previous chunk are carried over so a split straddling a chunk boundary is still seen."""
    chain = ctx.chain
    tr = [t for t in tr if not ctx.tokens.is_spoof(t["token"]) and int(t["frm"], 16) > 0xFFFF]
    froms = defaultdict(set)                  # batch txs (tokens of >= 3 different owners moved in one tx) are relayers
    for t in tr:
        froms[t["tx"]].add(t["frm"])
    ctx.xs_batch |= {h for h, f in froms.items() if len(f) >= 3}
    groups = detectors.xsplit_groups([t for t in ctx.xs_carry + tr if t["tx"] not in ctx.xs_batch], ctx.txs,
                                     ctx.is_allowed)
    last = max((t["block"] for t in tr), default=None)
    keep = int(XSPLIT_MAX_GAP / CHAINS[chain].get("block_sec", 12)) + 1     # blocks spanning the max gap
    ctx.xs_carry = [t for t in ctx.xs_carry + tr if last is not None and t["block"] >= last - keep]
    ctx.xs_batch &= {t["tx"] for t in ctx.xs_carry}
    ctx.stats["xsplit_groups"] += len(groups)
    if not groups:
        return
    ts = ctx.ts_of(sorted({x["block"] for legs in groups.values() for x in legs}))
    found = []
    for (caller, subject, victim, token), legs in groups.items():
        res = detectors.xsplit_confirm(legs, ts.get)
        if res:
            found.append((caller, subject, victim, token, res))
    if not found:
        return
    ctx.ensure_codes([x for f in found for x in (f[1], f[2])] + [r["wallet"] for f in found for r in f[4]["recipients"]])
    need = list(dict.fromkeys(x for f in found for x in (f[0], f[2]) if x not in ctx.nonce))
    if need:
        ctx.stats["nonce_lookups"] += len(need)
        ctx.nonce.update(ctx.rpc.nonces(need))
    ctx.tokens.ensure({f[3] for f in found})
    for caller, subject, victim, token, res in found:
        if victim not in ctx.code_hex or ctx.is_contract(victim) or (ctx.nonce.get(victim) or 0) < D8_MIN_VICTIM_NONCE:
            continue      # contract / custodial deposit address / unknown
        cn = ctx.nonce.get(caller)
        if subject != caller and (cn is None or cn >= D8_MAX_SPENDER_NONCE):
            continue      # puller contract driven by a high-volume relayer EOA (batch-transfer services: 11.8k / 119.5k
            #               nonces in the 2026-11-23 backtest). EOA spenders calling the token are NOT capped: two
            #               drain operators in the dev set split across txs with nonces 2.1k / 13.9k
        if subject == caller and ctx.is_contract(subject):
            continue
        if subject != caller and not ctx.is_contract(subject) and not ctx.is_delegated(subject):
            continue
        dec = ctx.tokens.get(token)[1]
        usd = [ctx.prices.usd(chain, token, x["value"], dec) for x in res["legs"]]
        if all(u is not None for u in usd) and sum(usd) < MIN_USD:
            continue
        first = res["txs"][0]
        det = dict(victims=[victim], token=token, caller=caller, txs=res["txs"], recipients=res["recipients"])
        if add_evidence_pending(ctx, "split_xtx", subject, first, res["legs"][0]["block"], det):
            update_payouts(ctx.conn, chain, subject, res["recipients"])
        for x in res["legs"]:
            ctx.pdr.append(ctx.drain_row(x, victim, subject))
        if ctx.is_contract(subject):
            ctx.d5(subject, first, res["legs"][0]["block"])
        ctx.stats["xsplit_confirmed"] += 1


K9_MAX_CODES = 300


def owner_collect(ctx, tr):
    """K9 (kit notes K1-K14): the caller of a contract pulls a third party's tokens to itself (Transfer.from =
    victim not in {tx.from, tx.to}, Transfer.to = tx.from) and the contract's dispatcher is the OwnerCollector kit
    (`owner_collector`) or the R-A2 owner-gated parametric puller. Subject = the contract, payout role `collector` =
    the caller/owner. No victim-nonce filter here: the code is kit-confirmed (the real victim had nonce 2)."""
    chain = ctx.chain
    cands = []
    for t in tr:
        tx = ctx.txs.get(t["tx"])
        if not tx or t["value"] == 0 or t["frm"] == ZERO or t["to"] == ZERO:
            continue
        caller, to = tx["from"], tx.get("to")
        if not to or to in (t["token"], PERMIT2) or t["to"] != caller or t["frm"] in (caller, to):
            continue
        if ctx.is_allowed(to) or ctx.is_allowed(caller) or ctx.is_allowed(t["frm"]):
            continue
        cands.append(t)
    if not cands:
        return
    ctx.ensure_codes([ctx.txs[t["tx"]]["to"] for t in cands], cap=K9_MAX_CODES)
    hits = []
    for t in cands:
        to = ctx.txs[t["tx"]]["to"]
        info = ctx.analysis(to)
        if info and (info.get("kit") == "owner_collector" or info.get("owner_gated_puller")):
            hits.append((t, to, info))
    if not hits:
        return
    ctx.ensure_codes([x for t, _, _ in hits for x in (t["frm"], t["to"])])
    ctx.tokens.ensure({t["token"] for t, _, _ in hits})
    for t, to, info in hits:
        if t["frm"] not in ctx.code_hex or ctx.is_contract(t["frm"]) or ctx.tokens.is_spoof(t["token"]):
            continue
        d = ctx.drain_row(t, t["frm"], to)
        if d["usd"] is not None and d["usd"] < MIN_USD:
            continue
        caller = t["to"]
        det = dict(victim=t["frm"], collector=caller, caller=caller, token=t["token"],
                   kit=info.get("kit") or "owner_gated_puller", operator_7702=ctx.is_delegated(caller))
        if add_evidence_pending(ctx, "owner_collect", to, t["tx"], t["block"], det):
            add_payout(ctx.conn, chain, to, caller, "collector")
        ctx.pdr.append(d)
        ctx.d5(to, t["tx"], t["block"])
        ctx.stats["k9_owner_collect"] += 1


def add_payout(conn, chain, drainer, wallet, role):
    """Payout wallet with a fixed role (customer: MS Drainer bait argument / withdraw caller; collector: D8 recipient).
    These roles are never re-ranked by update_payouts and carry no share."""
    if conn.execute("UPDATE payouts SET txs=txs+1 WHERE chain=? AND drainer=? AND wallet=?",
                    (chain, drainer, wallet)).rowcount == 0:
        conn.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES(?,?,?,?,NULL,1)",
                     (chain, drainer, wallet, role))


def add_evidence_pending(ctx, type_, address, tx, block, detail):
    """Emit evidence; True if (address,type,tx) is not stored yet (used to update payouts once per tx)."""
    exists = ctx.conn.execute("SELECT 1 FROM evidence WHERE chain=? AND address=? AND type=? AND tx=?",
                              (ctx.chain, address, type_, tx)).fetchone()
    ctx.emit(type_, address, tx, block, detail)
    return not exists


# ---------- ETH full-block pass: type-4, creations, red-flag payable ----------
def eth_block_pass(ctx, a, b, txmeta=None):
    rpc, conn = ctx.rpc, ctx.conn
    chain_id = CHAINS[ctx.chain]["id"]
    delegates = defaultdict(lambda: dict(n=0, delegators=[], tx=None, block=None))
    creations, redflag, withdraws, swaps, permits, pulls = [], [], [], [], [], []
    ap_txs = {a["tx"] for a in ctx.chunk_ap if a["kind"] == "approval"}
    inputs = {}                       # tx -> input for txs with Approval logs (K8 detail)
    bait_set = load_bait_set(ctx)
    recovered = 0
    nums = list(range(a, b + 1))
    for i in range(0, len(nums), 10):
        if time.monotonic() > ctx.deadline:
            ctx.stats["block_pass_cut"] = 1
            break
        for blk in rpc.blocks_full(nums[i:i + 10], chunk=5):
            if not blk:
                continue
            bn = hx(blk["number"])
            bts = hx(blk.get("timestamp"))
            for t in blk.get("transactions", []):
                ty = hx(t.get("type"))
                to = (t.get("to") or "").lower() or None
                if ty == 4:
                    ctx.stats["type4_txs"] += 1
                    for au in t.get("authorizationList") or []:
                        if hx(au.get("chainId")) not in (0, chain_id):
                            continue
                        d = delegates[au["address"].lower()]
                        d["n"] += 1
                        d["tx"] = d["tx"] or t["hash"]
                        d["block"] = d["block"] or bn
                        if recovered < MAX_AUTH_RECOVER and len(d["delegators"]) < 20:
                            who = authority_of(au)
                            recovered += 1
                            if who and who not in d["delegators"]:
                                d["delegators"].append(who)
                elif to is None:
                    creations.append((t["hash"], t["from"].lower(), bn))
                elif len(t.get("input", "")) >= 10:
                    inp = t["input"]
                    sel = inp[2:10].lower()
                    frm = t["from"].lower()
                    meta = dict(nonce=hx(t.get("nonce")), gas=hx(t.get("gas")), bts=bts)
                    if t["hash"] in ap_txs:
                        inputs[t["hash"]] = inp
                    if hx(t.get("value")) > 0 and sel in BAIT_CAPTURE:
                        redflag.append((t["hash"], to, sel, hx(t["value"]), frm, bn, inp, meta))
                    elif sel in MS_WITHDRAW_SELECTORS:      # kept only if `to` is a bait contract (checked after D7)
                        withdraws.append((t["hash"], to, sel, frm, bn, inp))
                    elif sel in PERMIT_SELECTORS:           # K4
                        pm = detectors.decode_permit(inp)
                        fields = detectors.ms_deadline_fields(pm)
                        if fields:
                            permits.append(dict(tx=t["hash"], frm=frm, to=to, block=bn, permit=pm, fields=fields))
                    elif sel in (SEL_TRANSFER_FROM, SEL_P2_TRANSFER_FROM, SEL_P2_TRANSFER_FROM_BATCH):   # K5
                        if meta["nonce"] <= ONESHOT_MAX_NONCE:
                            pulls.append((t["hash"], frm, to, bn, meta["nonce"], inp))
                    elif sel in SWAP_V2_SELECTORS or sel == SEL_MULTICALL_DEADLINE or \
                            SEL_V3_EXACT_INPUT_SINGLE in inp or SEL_R02_EXACT_INPUT_SINGLE in inp:
                        for sw in detectors.decode_swaps(inp):
                            c = detectors.d10_candidate(sw, frm, bts)
                            if c:
                                swaps.append(dict(c, tx=t["hash"], router=to, block=bn))
                elif to and hx(t.get("value")) > 0 and t.get("input", "0x") in ("0x", ""):
                    # plain native transfer: K5 fund / leftover return, K12 prefunding, K2 deployer "back" transfer
                    ctx.plain.append((t["from"].lower(), to, t["hash"], bn, hx(t.get("gas")), hx(t.get("value"))))
    ctx.stats["creations"] += len(creations)

    # D5 on top-level creations
    creations = creations[:MAX_CREATIONS]
    if txmeta is not None:     # receipts source: contractAddress already known
        rc = {h: {"contractAddress": m["created"], "status": hex(m["status"])} for h, m in txmeta.items() if m["created"]}
    else:
        rc = rpc.receipts([c[0] for c in creations])
    created = []
    for h, frm, bn in creations:
        r = rc.get(h)
        if r and r.get("contractAddress") and hx(r.get("status"), 1) == 1:
            created.append((r["contractAddress"].lower(), h, frm, bn))
    ctx.ensure_codes([c[0] for c in created])
    ts = ctx.ts_of(sorted({c[3] for c in created})) if created else {}
    for addr, h, frm, bn in created:
        found = ctx.d5(addr, h, bn, extra=dict(deployer=frm, creation=True))
        if found:
            conn.execute("INSERT OR IGNORE INTO creations(chain,address,deployer,tx,block,ts) VALUES(?,?,?,?,?,?)",
                         (ctx.chain, addr, frm, h, bn, ts.get(bn)))
            if found.get("kit") == "ms_generated":
                ctx.gen_created[addr] = (bn, frm)

    # D6 eip7702
    todo = [(d, v) for d, v in delegates.items() if ctx.seeds.has(ctx.chain, d) or v["n"] >= 2]
    todo.sort(key=lambda kv: -kv[1]["n"])
    todo = todo[:MAX_DELEGATE_CODES]
    ctx.ensure_codes([d for d, _ in todo])
    for d, v in todo:
        code = ctx.code_hex.get(d)
        seed = ctx.seeds.has(ctx.chain, d)
        heur = bool(code) and bytecode.is_sweeper_code(code)
        if seed or heur:
            ctx.emit("eip7702_sweeper", d, v["tx"], v["block"],
                     dict(authorizations=v["n"], delegators=v["delegators"],
                          reason="seed" if seed else "small contract: CALLVALUE+PUSH20+CALL, no SLOAD"))
        if code and code != "0x":
            ctx.d5(d, v["tx"], v["block"], extra=dict(delegate=True))
    ctx.stats["delegates"] += len(delegates)

    # D7 red-flag payable + bait(address) customers, withdraw callers; D10 foreign-recipient swaps
    ok = tx_status(ctx, [r[0] for r in redflag] + [x["tx"] for x in swaps] + [x["tx"] for x in permits]
                   + [x[0] for x in pulls], txmeta)
    if redflag:
        d7(ctx, [r for r in redflag if ok.get(r[0], True)])
    withdraws = [x for x in withdraws if x[1] in bait_set]
    ok.update(tx_status(ctx, [x[0] for x in withdraws], txmeta))
    for h, to, sel, frm, bn, inp in withdraws:
        if to not in bait_set or not ok.get(h, True):
            continue
        arg = "0x" + inp[34:74].lower() if len(inp) >= 74 else None
        if add_evidence_pending(ctx, "bait_withdraw", to, h, bn, dict(customer=frm, name=MS_WITHDRAW_SELECTORS[sel],
                                                                     withdraw_to=arg)):
            add_payout(conn, ctx.chain, to, frm, "customer")
    if swaps:
        d10(ctx, [x for x in swaps if ok.get(x["tx"], True)])
    if permits:
        k4(ctx, [x for x in permits if ok.get(x["tx"], True)])
    k5(ctx, [x for x in pulls if ok.get(x[0], True)], b)
    k7k8(ctx, inputs)
    gen_back(ctx, b)
    ctx.flush()


def tx_status(ctx, hashes, txmeta):
    """{tx: success} for the few txs the block pass flags. Receipts source: from txmeta; else one receipt each."""
    hashes = list(dict.fromkeys(hashes))
    if not hashes:
        return {}
    if txmeta is not None:
        return {h: txmeta[h]["status"] == 1 for h in hashes if h in txmeta}
    rc = ctx.rpc.receipts(hashes)
    return {h: hx(r.get("status"), 1) == 1 for h, r in rc.items()}


def load_bait_set(ctx):
    """Contracts known as MS-style bait: bait_payable evidence or ms_drainer kit bytecode (cached per scan)."""
    if ctx.bait_set is None:
        ctx.bait_set = set()
        for r in ctx.conn.execute("SELECT address,type,detail FROM evidence WHERE chain=? AND type IN "
                                  "('bait_payable','bytecode')", (ctx.chain,)):
            if r["type"] == "bait_payable" or json.loads(r["detail"] or "{}").get("kit") == "ms_drainer":
                ctx.bait_set.add(r["address"])
    return ctx.bait_set


def d7(ctx, redflag):
    """value>0 call with a red-flag / kit selector to a contract.
      * K1 MS_NEW 5-arg bait in the dispatcher, handler a third address -> `bait_payable` (kit ms_new): handler =
        customer, keeper = worker (payout roles), sender = victim (the depositer when the Wallet Randomizer is used);
      * K6 `kit_deposit`: MS_NEW Deposit sent by an EOA with tx nonce <= 2, gasLimit in {100k, 5M, 900k} and value >= 90 %
        of its balance before the block (balance check skipped -> recorded as unknown when the node has no archive);
      * K2 generated bait (`ms_generated`: exact runtime hash or code traits), its no-arg selector -> `bait_payable`
        (kit ms_generated): receivers read from storage (slot 1 main_receiver = customer, slot 2 fee receiver/percent);
        `fresh` when created <= 1 h before, `uses` counted;
      * bait(address) selector in the dispatcher and argument = a third address -> `bait_payable` (customer = argument;
        K3 `passthrough` when the contract is the pass-through variant, `balance_neutral` when its balance did not move);
      * otherwise `redflag_payable` (only for REDFLAG selectors; generator no-arg names alone are too generic)."""
    chain = ctx.chain
    ctx.ensure_codes([r[1] for r in redflag])
    native = CHAINS[chain]["native"]
    price = ctx.prices.native.get(native)
    for h, to, sel, val, frm, bn, inp, meta in redflag:
        if not ctx.is_contract(to) or ctx.is_allowed(to):
            continue
        info = ctx.persist_code(to)
        in_dispatch = bool(info) and sel in (info.get("selectors") or [])
        msn = detectors.decode_ms_new(inp) if sel in MS_NEW_SELECTORS else None
        dec = detectors.decode_bait(inp)
        kit = (info or {}).get("kit")

        def drain(recipient, k):
            ctx.pdr.append(dict(tx=h, li=-1, block=bn, victim=frm, drainer=to, token=ZERO, symbol=native, decimals=18,
                                amount=fmt_amount(val, 18), usd=round(val / 1e18 * price, 2) if price else None,
                                recipient=recipient))
            if ctx.bait_set is not None:
                ctx.bait_set.add(to)
            ctx.stats["d7_bait"] += 1
            ctx.stats["d7_" + k] += 1

        k6 = None
        if msn and sel == SEL_MS_NEW_DEPOSIT and meta["nonce"] <= KIT_DEPOSIT_MAX_NONCE and meta["gas"] in KIT_DEPOSIT_GAS:
            k6 = kit_deposit_share(ctx, frm, bn, val)
        if msn and in_dispatch and msn["handler"] not in (frm, to, ZERO) and int(msn["handler"], 16) > 0xFFFF:
            det = dict(selector=sel, name=msn["name"], value_wei=str(val), victim=frm, customer=msn["handler"],
                       worker=msn["keeper"], depositer=msn["depositer"], percent=msn["percent"], kit="ms_new")
            if add_evidence_pending(ctx, "bait_payable", to, h, bn, det):
                add_payout(ctx.conn, chain, to, msn["handler"], "customer")
                if msn["keeper"] not in (ZERO, msn["handler"]):
                    add_payout(ctx.conn, chain, to, msn["keeper"], "worker")
            drain(msn["handler"], "ms_new")
        elif kit == "ms_generated" and in_dispatch:
            gen_bait(ctx, h, to, sel, val, frm, bn, meta, info)
            drain(ctx.gen_receivers.get(to, {}).get("main") or to, "ms_generated")
        elif dec and in_dispatch and dec[2] not in (frm, to, ZERO) and int(dec[2], 16) > 0xFFFF:
            customer = dec[2]
            det = dict(selector=sel, name=dec[1], value_wei=str(val), victim=frm, customer=customer)
            if (info or {}).get("ms_variant") == "passthrough":
                det.update(passthrough=True, balance_neutral=balance_neutral(ctx, to, bn))
            if add_evidence_pending(ctx, "bait_payable", to, h, bn, det):
                add_payout(ctx.conn, chain, to, customer, "customer")
            drain(customer, "bait_address")
        elif sel in REDFLAG_SELECTORS:
            ctx.emit("redflag_payable", to, h, bn, dict(selector=sel, name=REDFLAG_SELECTORS[sel],
                                                        value_wei=str(val), sender=frm))
        if k6 is not None:
            ctx.emit("kit_deposit", to, h, bn, dict(depositer=frm, nonce=meta["nonce"], gas_limit=meta["gas"],
                                                    value_wei=str(val), balance_share=k6.get("share"),
                                                    handler=msn["handler"], keeper=msn["keeper"]))
            ctx.stats["k6_kit_deposit"] += 1
        ctx.d5(to, h, bn)


def kit_deposit_share(ctx, sender, bn, val):
    """K6 balance check: value / balance(sender, block - 1). Returns {} when unknown (no archive / fake rpc), None when
    the share is below 90 % (not a whole-balance sweep)."""
    fn = getattr(ctx.rpc, "balances", None)
    if fn is None:
        return {}
    try:
        bal = fn([(sender, bn - 1)]).get((sender, bn - 1))
    except Exception:  # noqa: BLE001 - best effort
        bal = None
    if not bal:
        return {}
    share = round(val / bal, 4)
    return dict(share=share) if share >= KIT_DEPOSIT_MIN_SHARE else None


def balance_neutral(ctx, addr, bn):
    """K3: True when the contract balance is the same before and after the block (all value forwarded), False when it
    changed, None when unknown (needs archive eth_getBalance; internal transfers are not visible without traces)."""
    fn = getattr(ctx.rpc, "balances", None)
    if fn is None:
        return None
    try:
        r = fn([(addr, bn - 1), (addr, bn)])
    except Exception:  # noqa: BLE001
        return None
    a, b = r.get((addr, bn - 1)), r.get((addr, bn))
    return None if a is None or b is None else a == b


def gen_bait(ctx, h, to, sel, val, frm, bn, meta, info):
    """K2 victim call to a generated bait contract: receivers from storage (slot 1: main_receiver; slot 2: fee_receiver |
    fee_percent << 160 | fee_state << 168), freshness (creation seen in this scan or the creations table), reuse count."""
    chain = ctx.chain
    rc = ctx.gen_receivers.get(to)
    if rc is None:
        rc = {}
        fn = getattr(ctx.rpc, "storage_many", None)
        if fn is not None:
            try:
                st = fn([(to, 1), (to, 2)])
            except Exception:  # noqa: BLE001
                st = {}
            s1, s2 = st.get((to, 1)), st.get((to, 2))
            if s1 is not None and s2 is not None:
                pct, state = (s2 >> 160) & 0xFF, (s2 >> 168) & 0xFF
                rc = dict(main="0x" + f"{s1 & ((1 << 160) - 1):040x}", fee="0x" + f"{s2 & ((1 << 160) - 1):040x}",
                          percent=pct if state and 1 <= pct <= 99 else 0)
        ctx.gen_receivers[to] = rc
    created = ctx.gen_created.get(to)
    if created is None:
        r = ctx.conn.execute("SELECT block, ts, deployer FROM creations WHERE chain=? AND address=?", (chain, to)).fetchone()
        created = (r["block"], r["deployer"]) if r else None
    fresh_sec = None
    if created:
        t = ctx.ts_of([created[0], bn])
        if t.get(created[0]) and t.get(bn):
            fresh_sec = t[bn] - t[created[0]]
    uses = 1 + ctx.conn.execute("SELECT COUNT(*) FROM evidence WHERE chain=? AND address=? AND type='bait_payable'",
                                (chain, to)).fetchone()[0] + sum(1 for e in ctx.pev if e["address"] == to
                                                                and e["type"] == "bait_payable")
    det = dict(selector=sel, name=BAIT_CAPTURE.get(sel), value_wei=str(val), victim=frm, kit="ms_generated",
               kit_exact=info.get("kit_exact"), customer=rc.get("main"), fee_receiver=rc.get("fee") if rc.get("percent") else None,
               fee_percent=rc.get("percent"), created_sec_before=fresh_sec,
               fresh=fresh_sec is not None and fresh_sec <= GEN_FRESH_SEC, uses=uses, over_reuse=uses > GEN_MAX_USES)
    if add_evidence_pending(ctx, "bait_payable", to, h, bn, det):
        if rc.get("main") and rc["main"] != ZERO:
            add_payout(ctx.conn, chain, to, rc["main"], "customer")
        if rc.get("percent") and rc.get("fee") not in (None, ZERO):
            add_payout(ctx.conn, chain, to, rc["fee"], "kit_fee")


def gen_back(ctx, last_block):
    """K2 deployer "back" transfer: after deploying a generated bait the kit sends the deployer's leftover to the
    operator wallet (plain native transfer from the deployer within GEN_BACK_WINDOW blocks of the creation)."""
    if not ctx.gen_created:
        return
    for addr, (cb, dep) in list(ctx.gen_created.items()):
        for frm, to, h, bn, gas, val in ctx.plain:
            if frm == dep and cb <= bn <= cb + GEN_BACK_WINDOW and to not in (addr, dep):
                if add_evidence_pending(ctx, "gen_back_transfer", addr, h, bn, dict(deployer=dep, wallet=to,
                                                                                    value_wei=str(val))):
                    add_payout(ctx.conn, ctx.chain, addr, to, "kit_wallet")
        if last_block > cb + GEN_BACK_WINDOW:
            del ctx.gen_created[addr]


def k4(ctx, permits):
    """K4 millisecond deadlines: permit / Permit2 calldata whose deadline / expiry / expiration / sigDeadline is in
    [1e12, 1e13]. Subject = the spender (allowance receiver; the submitter when the spender field is empty). A permit
    submitted by its own owner is not a kit permit. `pulled` = a Transfer from the owner in a tx sent by the submitter or
    the spender inside the same chunk (approval-then-pull) -> T1, else T2."""
    chain = ctx.chain
    for x in permits:
        pm = x["permit"]
        owner, subject = pm["owner"], pm["spender"] if pm["spender"] != ZERO else x["frm"]
        if owner in (x["frm"], subject) or ctx.is_allowed(subject) or ctx.is_allowed(owner):
            continue
        pulled = sorted({t["tx"] for t in ctx.chunk_tr if t["frm"] == owner and t["value"] > 0 and
                         (ctx.txs.get(t["tx"]) or {}).get("from") in (x["frm"], subject)} - {None})
        det = dict(victim=owner, submitter=x["frm"], kind=pm["kind"], fields=x["fields"],
                   values={k: str(pm["deadlines"][k]) for k in x["fields"]}, token=x["to"] if not pm["tokens"] else None,
                   tokens=pm["tokens"], pulled=bool(pulled), pull_txs=pulled[:5])
        ctx.emit("ms_deadline", subject, x["tx"], x["block"], det)
        ctx.stats["k4_ms_deadline"] += 1
        if subject != x["frm"] and not ctx.is_allowed(x["frm"]):
            add_payout(ctx.conn, chain, subject, x["frm"], "submitter")


def k5(ctx, pulls, last_block):
    """K5 / K12 one-shot EOA spenders. A pull (token.transferFrom / Permit2 transferFrom) sent by an EOA with tx nonce
    <= 3 for a third party, whose Transfer log really moved value (non-spoof token, >= 1 USD where priced), is kept as
    pending for ONESHOT_RETURN_WINDOW blocks. It is linked to a hub that sent the worker gas within ONESHOT_FUND_WINDOW
    blocks before (K12 `prefund`) and/or received the worker's leftover with gasLimit exactly 25 200 afterwards (K5
    `return`). Evidence `oneshot_spender` on the hub (worker, victim, token, pull/fund/return txs); payout role
    `worker` for the spender. Needs gas / nonce of every tx: ETH full-block pass only (both block sources)."""
    chain = ctx.chain
    trs = defaultdict(list)
    for t in ctx.chunk_tr:
        trs[t["tx"]].append(t)
    fresh = []
    for h, frm, to, bn, nonce, inp in pulls:
        for victim, rcpt, token in detectors.decode_pull_call(inp, to):
            token = token or to
            if victim in (frm, ZERO) or ctx.is_allowed(victim) or ctx.is_allowed(frm):
                continue
            legs = [t for t in trs.get(h, []) if t["frm"] == victim and t["token"] == token and t["value"] > 0]
            if legs:
                fresh.append(dict(tx=h, block=bn, worker=frm, victim=victim, token=token, recipient=legs[0]["to"],
                                  value=sum(t["value"] for t in legs), leg=legs[0], nonce=nonce))
    if fresh:
        ctx.tokens.ensure({x["token"] for x in fresh})
        ctx.ensure_codes([y for x in fresh for y in (x["worker"], x["victim"])])
    for x in fresh:
        if ctx.tokens.is_spoof(x["token"]) or ctx.is_contract(x["worker"]) or x["victim"] not in ctx.code_hex                 or ctx.is_contract(x["victim"]):
            continue
        d = ctx.drain_row(dict(x["leg"], value=x["value"]), x["victim"], x["worker"])
        if d["usd"] is not None and d["usd"] < MIN_USD:
            continue
        x["drain"] = d
        ctx.k5_pulls[x["worker"]].append(x)
    ctx.plain = [p for p in ctx.plain if p[3] >= last_block - ONESHOT_KEEP]
    if not ctx.k5_pulls:
        return
    funds, rets = defaultdict(list), defaultdict(list)
    for frm, to, h, bn, gas, val in ctx.plain:
        if to in ctx.k5_pulls:
            funds[to].append((frm, h, bn))
        if frm in ctx.k5_pulls and gas == ONESHOT_RETURN_GAS:
            rets[frm].append((to, h, bn))
    links = detectors.oneshot_links(ctx.k5_pulls, funds, rets, ONESHOT_FUND_WINDOW, ONESHOT_RETURN_WINDOW)
    links = [ln for ln in links if not ctx.is_allowed(ln["hub"])]
    if links:
        ctx.ensure_codes([ln["hub"] for ln in links])
    for ln in links:
        p, hub = ln["pull"], ln["hub"]
        if ctx.is_contract(hub):
            continue                    # hubs are EOAs (plain or EIP-7702-delegated)
        key = ln["return_tx"] or p["tx"]
        det = dict(worker=ln["worker"], victim=p["victim"], token=p["token"], recipient=p["recipient"], pull_tx=p["tx"],
                   worker_nonce=p["nonce"], fund_tx=ln["fund_tx"], return_tx=ln["return_tx"],
                   hub_7702=ctx.is_delegated(hub))
        if add_evidence_pending(ctx, "oneshot_spender", hub, key, p["block"], det):
            add_payout(ctx.conn, chain, hub, ln["worker"], "worker")
            if p["recipient"] not in (hub, ln["worker"]):
                add_payout(ctx.conn, chain, hub, p["recipient"], "collector")
            ctx.pdr.append(dict(p["drain"], drainer=hub))
            ctx.stats["k5_oneshot"] += 1
    for w in list(ctx.k5_pulls):
        ctx.k5_pulls[w] = [p for p in ctx.k5_pulls[w] if p["block"] >= last_block - ONESHOT_RETURN_WINDOW]
        if not ctx.k5_pulls[w]:
            del ctx.k5_pulls[w]


def k7k8(ctx, inputs):
    """K7 EIP-5792 batch approvals / K8 kit-amount approval to a legitimate router, both followed in the same tx by a
    drain to a foreign EOA (owner loses tokens, gets nothing back). Subject = each EOA recipient. V3 exactInputSingle
    parameters found in the tx calldata (fee, deadline delta, amountOutMinimum) are kept as detail."""
    if not ctx.chunk_ap:
        return
    aps, trs = defaultdict(list), defaultdict(list)
    for a in ctx.chunk_ap:
        aps[a["tx"]].append(a)
    for t in ctx.chunk_tr:
        if t["tx"] in aps:
            trs[t["tx"]].append(t)
    hits = []
    for h, al in aps.items():
        if len(al) < 1 or h not in trs:
            continue
        for c in detectors.k7k8_tx(al, trs[h], KIT_APPROVAL_AMOUNTS, ctx.is_allowed):
            hits.append((h, al[0]["block"], c))
    if not hits:
        return
    ctx.ensure_codes([x for _, _, c in hits for x in [c["owner"]] + list(c["recipients"])])
    for h, bn, c in hits:
        if c["owner"] not in ctx.code_hex or ctx.is_contract(c["owner"]):
            continue
        bts = (ctx.ts_of([bn]).get(bn) or 0)
        v3 = [dict(fee=s["fee"], deadline_delta=(s["deadline"] - bts) if s.get("deadline") and bts else None,
                   amount_out_min=str(s["amount_out_min"]), recipient=s["to"])
              for s in detectors.decode_v3_singles(detectors._hexbytes(inputs.get(h)))] if inputs.get(h) else []
        for r, legs in c["recipients"].items():
            if r not in ctx.code_hex or ctx.is_contract(r):
                continue
            det = dict(victim=c["owner"], approvals=c["approvals"][:10], legs=legs[:10], kit=c["kit"], v3=v3[:3])
            if add_evidence_pending(ctx, c["rule"], r, h, bn, det):
                ctx.tokens.ensure({lg["token"] for lg in legs})
                for i, lg in enumerate(legs):
                    leg = dict(tx=h, li=-10 - i, block=bn, token=lg["token"], value=int(lg["value"]), to=r)
                    ctx.pdr.append(ctx.drain_row(leg, c["owner"], r))
            ctx.stats["k7k8_" + c["rule"]] += 1


def d10(ctx, swaps):
    """Victim-signed swap paying a foreign EOA with amountOutMin = 0 (MS Drainer kit notes S4). The recipient is the
    subject ("drainer receiver"); victim = tx.from; the token sold is recorded as a drain."""
    chain = ctx.chain
    swaps = [x for x in swaps if not ctx.is_allowed(x["recipient"]) and not ctx.is_allowed(x["victim"])]
    if not swaps:
        return
    ctx.ensure_codes([x["recipient"] for x in swaps] + [x["victim"] for x in swaps])
    ctx.tokens.ensure({x["token"] for x in swaps})
    for x in swaps:
        r = x["recipient"]
        if r not in ctx.code_hex or ctx.is_contract(r) or ctx.is_contract(x["victim"]):
            continue
        if ctx.tokens.is_spoof(x["token"]):
            continue
        sym, dec = ctx.tokens.get(x["token"])
        v = int(x["amount_in"])
        usd = ctx.prices.usd(chain, x["token"], v, dec)
        det = {k: x[k] for k in ("victim", "token", "token_out", "amount_in", "fn", "deadline_delta", "kit", "router")}
        det["usd"] = usd          # multi-victim rule counts only priced sales (meme-token wallet farms are unpriced)
        ctx.emit("foreign_recipient_swap", r, x["tx"], x["block"], det)
        ctx.pdr.append(dict(tx=x["tx"], li=-2, block=x["block"], victim=x["victim"], drainer=r, token=x["token"],
                            symbol=sym, decimals=dec, amount=fmt_amount(v, dec), usd=usd, recipient=r))
        ctx.stats["d10_confirmed"] += 1


# ---------- per-chain driver ----------
def scan_chain(conn, chain, seeds, labels, prices, max_blocks=None, deadline=None, rpc=None, start=None, end=None,
               persist_cursor=True, source=None, code_cache=None, family_index=None):
    """Scan from the stored cursor (or [start, end] for backtest). Returns a stats dict.
    source: 'logs' (eth_getLogs) or 'receipts' (eth_getBlockReceipts); default env DRAINERWATCH_SOURCE, else the
    per-chain default CHAINS[chain]['source'] (receipts on ETH/Base, logs on BSC)."""
    cfg = CHAINS[chain]
    rpc = rpc or Rpc(chain)
    deadline = deadline or (time.monotonic() + 600)
    source = (source or env("DRAINERWATCH_SOURCE", "") or cfg.get("source", "logs")).lower()
    ctx = Ctx(conn, chain, rpc, seeds, labels, prices, deadline, code_cache=code_cache, family_index=family_index)
    head = rpc.block_number()
    if start is None:
        cur = meta_get(conn, f"cursor:{chain}")
        start = int(cur) + 1 if cur else max(1, head - INITIAL_BLOCKS)
        end = min(head - CONFIRMATIONS, start + (max_blocks or cfg["max_blocks"]) - 1)
    meta_set(conn, f"head:{chain}", head)
    st = ctx.stats
    st["head"], st["start"] = head, start
    done = start - 1
    if end >= start:
        load_state(ctx)
        try:
            ctx.fetch_seed_codes()
        except Exception as e:  # noqa: BLE001
            log.warning("%s: seed code fetch failed: %s", chain, e)
        size = int(meta_get(conn, f"chunk:{chain}", cfg["chunk"]) or cfg["chunk"])
        if source == "receipts":
            chunks = rpc.iter_receipts(start, end, deadline, size=min(size, 10))
        else:
            chunks = ((x, y, lg, None) for x, y, lg in rpc.iter_logs(start, end, deadline, size))
        for a, b, logs, txmeta in chunks:
            process_chunk(ctx, a, b, logs, txmeta=txmeta)
            if chain == "eth":
                try:
                    eth_block_pass(ctx, a, b, txmeta=txmeta)
                except Exception as e:  # noqa: BLE001
                    log.warning("eth block pass %s-%s failed: %s", a, b, e)
            done = b
            if persist_cursor:
                meta_set(conn, f"cursor:{chain}", done)
                meta_set(conn, f"scan_at:{chain}", now_ts())
                conn.commit()
        if source != "receipts":
            meta_set(conn, f"chunk:{chain}", max(1, rpc.last_size or size))
    elif persist_cursor:
        meta_set(conn, f"scan_at:{chain}", now_ts())
    conn.commit()
    st["end"], st["done"] = end, done
    st["blocks"] = max(0, done - start + 1)
    st["lag"] = max(0, head - done)
    st["rpc_calls"], st["rpc_limit_hits"], st["rpc_errors"] = rpc.calls, rpc.limit_hits, rpc.errors
    st["source"] = source
    return st
