"""TRON ingestion and detectors T-1..T-8 (see tron_detectors). Writes the same chain-agnostic tables as scan.py
(evidence / drains / payouts / codes / contract_deployer) with base58 addresses and chain = 'tron'.

Per chunk of blocks: getblockbylimitnext (every tx with contract type, owner, calldata, call value, fee limit,
signatures) + gettransactioninfobyblocknum per block (TRC-20 Transfer/Approval logs, fee, energy, internal TRX)."""
import json
import logging
import time
from collections import defaultdict

from . import bytecode, detectors, enrich
from . import tron_detectors as td
from .constants import (CHAINS, MIN_USD, TRON_ALLOWLIST, TRON_FEE_WINDOW, TRON_KIT_FEE_LIMIT,
                        TRON_MAX_ACCOUNT_LOOKUPS, TRON_MAX_CONTRACT_LOOKUPS, TRON_PERM_MIN_AGE_SEC, TRON_POISON_MIN,
                        TRON_HUB_MAX_FUNDED, TRON_PREFUND_KEEP, TRON_PREFUND_MAX, TRON_PREFUND_MIN, TRON_PREFUND_MIN_GAP,
                        TRON_PREFUND_WINDOW, TRON_USDT,
                        XSPLIT_MAX_GAP)
from .db import meta_get, meta_set
from .scan import Ctx, add_evidence_pending, add_payout, load_state, plan_range, update_payouts
from .seeds import load_allowlist
from .tron import TRON_ZERO, TronRpc, is_tron_addr, parse_block, parse_infos, signer_of
from .util import HttpError, now_ts

log = logging.getLogger("drainerwatch.tron_scan")
CHAIN = "tron"
PULL_KITS = {"verify_account", "owner_collector", "ms_drainer", "buytron_swap_trx", "buytron_swap_proxy"}     # dispatcher fingerprints that pull third parties
CARRY_SEC = max(XSPLIT_MAX_GAP, TRON_FEE_WINDOW, 600)


class TronCtx(Ctx):
    """scan.Ctx with TRON lookups: contract info (runtime + creator) cached in tron_contracts, accounts (create_time,
    balance) cached per run, base58 allowlist."""
    tvm = True

    def __init__(self, conn, rpc, seeds, labels, prices, deadline=None):
        super().__init__(conn, CHAIN, rpc, seeds, labels, prices, deadline)
        self.allow = set(TRON_ALLOWLIST) | {a for a in load_allowlist(CHAIN) if is_tron_addr(a)}
        self.full_txs = True
        self.cinfo_mem: dict = {}
        self.acct_mem: dict = {}
        self.ptx: dict = {}            # txid -> parsed tx (current chunk + carry)
        self.carry: list = []          # parsed txs of the last CARRY_SEC seconds
        self.tr_carry: list = []       # third-party pull legs of the last CARRY_SEC seconds
        self.aml_pending: list = []    # T-3 aml_exact candidates waiting for the bait transfer
        self.hijacked: dict = {}       # T-6 victim -> {controller}
        self.tokens.cache[TRON_ZERO] = ("TRX", 6)

    # ---- lookups ----
    def cinfo(self, addr, fetch=True):
        """dict(is_contract, size, kit, puller, origin, name, selectors) or None (unknown / lookup cap reached)."""
        if not is_tron_addr(addr):
            return None
        if addr in self.cinfo_mem:
            return self.cinfo_mem[addr]
        r = self.conn.execute("SELECT * FROM tron_contracts WHERE address=?", (addr,)).fetchone()
        if r:
            info = dict(r)
            info["selectors"] = json.loads(info.get("selectors") or "[]")
            self.cinfo_mem[addr] = info
            if not info["is_contract"]:
                self.code_hex.setdefault(addr, "0x")
            return info
        if not fetch:
            return None
        if self.stats["contract_lookups"] >= TRON_MAX_CONTRACT_LOOKUPS:
            self.stats["contract_lookups_capped"] += 1
            return None
        self.stats["contract_lookups"] += 1
        try:
            ci = self.rpc.contract_info(addr)
        except HttpError as e:
            log.debug("contract info %s: %s", addr, e)
            return None
        if ci and ci.get("runtime"):
            code = "0x" + ci["runtime"]
            self.code_hex[addr] = code
            a = bytecode.analyze(code, tvm=True)
            info = dict(is_contract=1, size=a["size"], kit=a.get("kit"), puller=int(bool(a.get("owner_gated_puller"))),
                        origin=ci.get("origin"), name=ci.get("name"), selectors=a["selectors"])
            if ci.get("origin"):
                self.conn.execute("INSERT OR IGNORE INTO contract_deployer(chain,address,deployer,tx,via,factory,"
                                  "resolved_at,block) VALUES(?,?,?,?,?,?,?,?)",
                                  (CHAIN, addr, ci["origin"], None, "getcontract", None, now_ts(), None))
        else:
            self.code_hex[addr] = "0x"
            info = dict(is_contract=0, size=0, kit=None, puller=0, origin=None, name=None, selectors=[])
        self.conn.execute("INSERT OR REPLACE INTO tron_contracts(address,is_contract,size,kit,puller,origin,name,selectors,"
                          "checked_at) VALUES(?,?,?,?,?,?,?,?,?)",
                          (addr, info["is_contract"], info["size"], info["kit"], info["puller"], info["origin"],
                           info["name"], json.dumps(info["selectors"]), now_ts()))
        self.cinfo_mem[addr] = info
        return info

    def is_contract(self, addr):
        i = self.cinfo(addr, fetch=False)
        return bool(i and i["is_contract"])

    def ensure_codes(self, addrs, cap=None):
        for a in list(dict.fromkeys(addrs))[:cap or TRON_MAX_CONTRACT_LOOKUPS]:
            self.cinfo(a)

    def account(self, addr):
        """getaccount (cached per run): {} for a never-activated address, None on error / cap."""
        if addr in self.acct_mem:
            return self.acct_mem[addr]
        if self.stats["account_lookups"] >= TRON_MAX_ACCOUNT_LOOKUPS:
            return None
        self.stats["account_lookups"] += 1
        a = self.rpc.account(addr)
        self.acct_mem[addr] = a
        return a

    def created_ts(self, addr):
        a = self.account(addr)
        if a is None:
            return None
        return int(a["create_time"]) // 1000 if a.get("create_time") else 0

    def fetch_seed_codes(self, cap=50):
        todo = [a for a in self.seeds.addresses(CHAIN) if is_tron_addr(a)][:cap]
        for a in todo:
            self.cinfo(a)
        return len(todo)

    def bytecode_ev(self, addr, tx, block, extra=None):
        """d5 (bytecode evidence, once per address) with the runtime fetched if this run has not seen it yet."""
        if self.conn.execute("SELECT 1 FROM evidence WHERE chain=? AND address=? AND type='bytecode' LIMIT 1",
                             (CHAIN, addr)).fetchone():
            return None
        if self.code_hex.get(addr, "0x") == "0x":
            try:
                ci = self.rpc.contract_info(addr)
            except HttpError:
                return None
            if not ci or not ci.get("runtime"):
                return None
            self.code_hex[addr] = "0x" + ci["runtime"]
        return self.d5(addr, tx, block, extra)

    def allowed_any(self, *addrs):
        return any(a and self.is_allowed(a) for a in addrs)


# ---------- chunk ----------
def process_tron_chunk(ctx, blocks, infos):
    """blocks: raw `visible: true` blocks; infos: {block number: tx-info list | None}."""
    conn = ctx.conn
    txs = [t for b in blocks for t in parse_block(b)]
    tr, ap, meta = [], [], {}
    for b in blocks:
        n = int(b["block_header"]["raw_data"].get("number", 0))
        inf = infos.get(n)
        if inf is None:
            ctx.stats["info_missing"] += 1
            continue
        t1, a1, m1 = parse_infos(inf, n)
        tr += t1
        ap += a1
        meta.update(m1)
    for t in txs:
        t["fee"] = (meta.get(t["h"]) or {}).get("fee", 0)
    ts_of = {t["h"]: t["ts"] for t in txs}
    for x in tr + ap:
        x["ts"] = ts_of.get(x["tx"])
    last_ts = max((t["ts"] for t in txs), default=now_ts())
    ctx.carry = [t for t in ctx.carry if last_ts - t["ts"] <= CARRY_SEC]
    ctx.ptx = {t["h"]: t for t in ctx.carry + txs}
    ctx.txs = {h: {"from": t["frm"], "to": t["to"], "block": t["block"]} for h, t in ctx.ptx.items()}
    ctx.stats["txs"] += len(txs)
    ctx.stats["logs"] += len(tr) + len(ap)
    ctx.stats["transfers"] += len(tr)
    ctx.stats["approvals"] += len(ap)

    seeds_and_fingerprints(ctx, tr, ap)
    record_fundings(ctx, txs, last_ts)
    calls = td.approval_calls(txs)
    approvals_t3(ctx, calls)
    prefund_t4(ctx, calls)
    pulls = pulls_t1(ctx, tr)
    xsplit_t1(ctx, pulls)
    single_split(ctx, tr)
    bait_t5(ctx, txs)
    perms_t6(ctx, txs, tr)
    fees_t7(ctx, pulls, txs, last_ts)
    poison_t8(ctx, tr)

    ctx.carry = [t for t in ctx.carry + txs if last_ts - t["ts"] <= CARRY_SEC]
    ctx.flush()
    from .scan import refresh_known
    refresh_known(ctx)
    try:
        enrich.vasp_scan_chunk(ctx, [t for t in tr if t["value"] > 0])
    except Exception as e:  # noqa: BLE001 - best effort
        log.warning("tron: vasp pass failed: %s", e)
    conn.commit()


def seeds_and_fingerprints(ctx, tr, ap):
    ev1, legs1 = detectors.d1_seed_activity(CHAIN, tr, ap, ctx.seeds)
    for e in ev1:
        ctx.emit(e["type"], e["address"], e["tx"], e["block"], e["detail"])
    if legs1:
        ctx.tokens.ensure([t["token"] for t in legs1])
        for t in legs1:
            ctx.pdr.append(ctx.drain_row(t, t["frm"], t["to"]))
    for c in detectors.d9_candidates(ap, ctx.is_allowed):
        if c["spender"] in (TRON_ZERO, c["owner"]):
            continue
        ctx.emit("approval_fingerprint", c["spender"], c["tx"], c["block"],
                 dict(victim=c["owner"], token=c["token"], kit=c["kit"]))


# ---------- T-3 ----------
def labelled(ctx, addr):
    return (CHAIN, addr) in ctx.labels


def approvals_t3(ctx, calls):
    ctx.aml_pending = [c for c in ctx.aml_pending if c["tx"] in ctx.ptx]
    for c in calls:
        kind = td.approval_kind(c)
        if not kind or ctx.allowed_any(c["spender"]) or labelled(ctx, c["spender"]):
            continue
        det = dict(victim=c["owner"], token=c["token"], kind=kind, method=c["method"],
                   fee_limit_trx=c["fee_limit"] // 1_000_000, amount=None if c["amount"] is None else str(c["amount"]))
        if kind == "aml_exact":
            ctx.aml_pending.append(c)
            continue
        if kind == "kit_amount":
            det["kit"] = "tron_1e46"
            if c["fee_limit"] == TRON_KIT_FEE_LIMIT:
                ctx.emit("approval_fingerprint", c["spender"], c["tx"], c["block"],
                         dict(victim=c["owner"], token=c["token"], kit="tron_1e46_fee35"))
                ctx.stats["t3_fingerprint"] += 1
                continue
        if kind == "increase_max":
            info = ctx.cinfo(c["spender"])
            if info is None:
                continue
            if info["is_contract"]:
                if not (info["kit"] or info["puller"]):
                    continue
                det["spender_kit"] = info["kit"] or "owner_gated_puller"
            else:
                cr = ctx.created_ts(c["spender"])
                if cr is None or (cr and c["ts"] - cr > TRON_PERM_MIN_AGE_SEC):
                    continue                      # spender with > 30 days of history: not a fresh drainer key
                det["fresh_spender"] = True
        ctx.emit("tron_approval", c["spender"], c["tx"], c["block"], det)
        ctx.stats["t3_" + kind] += 1
    if ctx.aml_pending:
        hits = td.aml_followups(ctx.aml_pending, list(ctx.ptx.values()))
        done = set()
        for c, ttx in hits:
            ctx.emit("tron_approval", c["spender"], c["tx"], c["block"],
                     dict(victim=c["owner"], token=c["token"], kind="aml_exact", method=c["method"],
                          fee_limit_trx=c["fee_limit"] // 1_000_000, amount=str(c["amount"]), transfer_tx=ttx["h"]))
            done.add(c["tx"])
            ctx.stats["t3_aml_exact"] += 1
        ctx.aml_pending = [c for c in ctx.aml_pending if c["tx"] not in done]


# ---------- T-4 ----------
def record_fundings(ctx, txs, last_ts):
    rows = td.small_fundings(txs, TRON_PREFUND_MIN, TRON_PREFUND_MAX)
    ctx.conn.executemany("INSERT OR IGNORE INTO tron_fund(funder,recipient,amount,tx,ts,block) VALUES(?,?,?,?,?,?)", rows)
    ctx.conn.execute("DELETE FROM tron_fund WHERE ts < ?", (last_ts - TRON_PREFUND_KEEP,))
    ctx.stats["fundings"] += len(rows)


def prefund_t4(ctx, calls):
    for c in calls:
        if c["amount"] == 0 or ctx.allowed_any(c["spender"]):
            continue
        rows = ctx.conn.execute("SELECT funder,amount,tx,ts FROM tron_fund WHERE recipient=? AND ts BETWEEN ? AND ?",
                                (c["owner"], c["ts"] - TRON_PREFUND_WINDOW, c["ts"])).fetchall()
        if not rows:
            continue
        funders = {r["funder"] for r in rows}
        origin = None
        if c["spender"] not in funders:
            info = ctx.cinfo(c["spender"])
            origin = info and info.get("origin")
            if origin not in funders:
                continue
        f = c["spender"] if c["spender"] in funders else origin
        if ctx.allowed_any(f) or labelled(ctx, f):
            continue
        r = max((r for r in rows if r["funder"] == f), key=lambda r: r["ts"])
        if c["ts"] - r["ts"] < TRON_PREFUND_MIN_GAP:
            continue                      # funded in the same block as the approval: sponsored-transaction relayer
        fan = ctx.conn.execute("SELECT COUNT(DISTINCT recipient) FROM tron_fund WHERE funder=?", (f,)).fetchone()[0]
        if fan > TRON_HUB_MAX_FUNDED:
            continue                      # TRX distribution hub (exchange / energy service), not an operator
        ctx.emit("prefund_approve", f, c["tx"], c["block"],
                 dict(victim=c["owner"], spender=c["spender"], amount_trx=r["amount"] // 1_000_000, fund_tx=r["tx"],
                      sec_before=c["ts"] - r["ts"], spender_creator=origin == f))
        if c["spender"] != f:
            add_payout(ctx.conn, CHAIN, c["spender"], f, "funder")
        ctx.stats["t4_prefund"] += 1


# ---------- T-1 / T-2 ----------
def pulls_t1(ctx, tr):
    """Third-party pulls; through a kit / owner-gated contract -> kit_pull. Returns the pull legs (with ts) for the
    cross-tx split and fixed-fee rules."""
    pulls = [p for p in td.third_party_pulls(tr, ctx.ptx)
             if not ctx.allowed_any(p["subject"], p["caller"], p["to"], p["frm"]) and not ctx.tokens.is_spoof(p["token"])]
    for p in pulls:
        p["ts"] = ctx.ptx[p["tx"]]["ts"]
    ctx.stats["pull_legs"] += len(pulls)
    subjects = list(dict.fromkeys(p["subject"] for p in pulls if p["via"] == "contract"))
    hits = []
    for s in subjects:
        info = ctx.cinfo(s)
        if info and info["is_contract"] and (info["kit"] in PULL_KITS or info["puller"]):
            hits.append(s)
    if hits:
        hs = set(hits)
        ctx.tokens.ensure({p["token"] for p in pulls if p["subject"] in hs})
        for p in pulls:
            if p["subject"] not in hs:
                continue
            vi = ctx.cinfo(p["frm"])
            if vi is None or vi["is_contract"]:
                continue
            d = ctx.drain_row(p, p["frm"], p["subject"])
            if d["usd"] is not None and d["usd"] < MIN_USD:
                continue
            info = ctx.cinfo(p["subject"])
            det = dict(victim=p["frm"], caller=p["caller"], recipient=p["to"], token=p["token"],
                       kit=info["kit"] or "owner_gated_puller", caller_is_creator=info.get("origin") == p["caller"])
            if add_evidence_pending(ctx, "kit_pull", p["subject"], p["tx"], p["block"], det):
                add_payout(ctx.conn, CHAIN, p["subject"], p["to"], "collector")
            ctx.pdr.append(d)
            ctx.bytecode_ev(p["subject"], p["tx"], p["block"])
            ctx.stats["t1_kit_pull"] += 1
    # EOA spender pulls (transferFrom on the token) by a spender with a TRON kit approval on record (T-3 -> pull)
    eoa = [p for p in pulls if p["via"] == "token"]
    if eoa:
        flagged = {r["address"] for r in ctx.conn.execute(
            "SELECT DISTINCT address FROM evidence WHERE chain=? AND type IN ('tron_approval','approval_fingerprint') "
            "AND address IN (%s)" % ",".join("?" * len({p['subject'] for p in eoa})), (CHAIN, *{p["subject"] for p in eoa}))}
        flagged |= {e["address"] for e in ctx.pev if e["type"] in ("tron_approval", "approval_fingerprint")}
        for p in eoa:
            if p["subject"] not in flagged:
                continue
            d = ctx.drain_row(p, p["frm"], p["subject"])
            if d["usd"] is not None and d["usd"] < MIN_USD:
                continue
            if add_evidence_pending(ctx, "eoa_spender_pull", p["subject"], p["tx"], p["block"],
                                    dict(victim=p["frm"], recipient=p["to"], token=p["token"], via="transferFrom")):
                add_payout(ctx.conn, CHAIN, p["subject"], p["to"], "collector")
            ctx.pdr.append(d)
            ctx.stats["t3_eoa_pull"] += 1
    return pulls


def xsplit_t1(ctx, pulls):
    """R-A1 on TRON (case A: two Verify20 txs of the same caller in the same block, 98/2)."""
    last = max((p["ts"] for p in pulls), default=None)
    legs = ctx.tr_carry + pulls
    if last is not None:
        ctx.tr_carry = [p for p in legs if last - p["ts"] <= XSPLIT_MAX_GAP]
    groups = detectors.xsplit_groups(legs, ctx.txs, ctx.is_allowed)
    ctx.stats["xsplit_groups"] += len(groups)
    if not groups:
        return
    ts = {p["block"]: p["ts"] for p in legs}
    for (caller, subject, victim, token), g in groups.items():
        res = detectors.xsplit_confirm(g, ts.get)
        if not res:
            continue
        vi = ctx.cinfo(victim)
        if vi is None or vi["is_contract"]:
            continue
        si = ctx.cinfo(subject)
        if si is None or (subject == caller and si["is_contract"]) or (subject != caller and not si["is_contract"]):
            continue
        ctx.tokens.ensure([token])
        dec = ctx.tokens.get(token)[1]
        usd = [ctx.prices.usd(CHAIN, token, x["value"], dec) for x in res["legs"]]
        if all(u is not None for u in usd) and sum(usd) < MIN_USD:
            continue
        first = res["txs"][0]
        det = dict(victims=[victim], token=token, caller=caller, txs=res["txs"], recipients=res["recipients"])
        if add_evidence_pending(ctx, "split_xtx", subject, first, res["legs"][0]["block"], det):
            update_payouts(ctx.conn, CHAIN, subject, res["recipients"])
        for x in res["legs"]:
            ctx.pdr.append(ctx.drain_row(x, victim, subject))
        if si["is_contract"]:
            ctx.bytecode_ev(subject, first, res["legs"][0]["block"])
        ctx.stats["xsplit_confirmed"] += 1


def single_split(ctx, tr):
    """D2 on TRON: one tx pulls a third party's token and splits it to 2-3 recipients (largest share 0.60-0.95) through a
    non-allowlisted contract (NiceCrypto 80/20 shape)."""
    legs = [t for t in tr if TRON_ZERO not in (t["frm"], t["to"])]
    for c in detectors.d2_candidates(legs, ctx.is_allowed):
        tx = ctx.ptx.get(c["tx"])
        if not tx or not tx["ok"] or not tx["to"] or c["victim"] in (tx["frm"], tx["to"]) or tx["to"] == c["token"]:
            continue
        if not 2 <= len(c["per"]) <= 3 or ctx.allowed_any(tx["to"], *c["per"]) or any(labelled(ctx, w) for w in c["per"]):
            continue
        if any(w in (tx["to"], tx["frm"]) for w in c["per"]):
            continue
        ti, vi = ctx.cinfo(tx["to"]), ctx.cinfo(c["victim"])
        if not ti or not ti["is_contract"] or vi is None or vi["is_contract"]:
            continue
        ctx.tokens.ensure([c["token"]])
        dec = ctx.tokens.get(c["token"])[1]
        usd = [ctx.prices.usd(CHAIN, c["token"], x["value"], dec) for x in c["legs"]]
        if all(u is not None for u in usd) and sum(usd) < MIN_USD:
            continue
        ranked = sorted(c["per"].items(), key=lambda kv: -kv[1])
        rec = [dict(wallet=w, share=round(s, 4), role="affiliate" if i == 0 else "operator") for i, (w, s) in enumerate(ranked)]
        det = dict(victims=[c["victim"]], token=c["token"], recipients=rec)
        if add_evidence_pending(ctx, "split_pull", tx["to"], c["tx"], c["block"], det):
            update_payouts(ctx.conn, CHAIN, tx["to"], rec)
        for x in c["legs"]:
            ctx.pdr.append(ctx.drain_row(x, c["victim"], tx["to"]))
        ctx.bytecode_ev(tx["to"], c["tx"], c["block"])
        ctx.stats["d2_confirmed"] += 1


# ---------- T-5 ----------
def bait_t5(ctx, txs):
    for b in td.bait_calls(txs):
        if ctx.allowed_any(b["contract"]):
            continue
        info = ctx.cinfo(b["contract"])
        if not info or not info["is_contract"]:
            continue
        if not (info["kit"] or set(info["selectors"]) & set(td.BAIT_ADDR_SELECTORS)):
            continue
        acc = ctx.account(b["victim"])
        shape = None
        if acc is not None:
            later = int(acc.get("latest_opration_time") or 0) // 1000
            if later <= b["ts"] + 3:      # no newer activity: the current balance is the post-call balance
                fee = (ctx.ptx.get(b["tx"]) or {}).get("fee", 0)
                shape = td.claimer_shape(b["value"], int(acc.get("balance") or 0), fee)
        det = dict(victim=b["victim"], value_wei=str(b["value"]), unit="sun", name=b["name"], customer=b["customer"],
                   kit=info["kit"], claimer_shape=shape)
        if add_evidence_pending(ctx, "bait_payable", b["contract"], b["tx"], b["block"], det) and b["customer"]:
            add_payout(ctx.conn, CHAIN, b["contract"], b["customer"], "customer")
        ctx.pdr.append(dict(tx=b["tx"], li=-1, block=b["block"], victim=b["victim"], drainer=b["contract"],
                            token=TRON_ZERO, symbol="TRX", decimals=6, amount=str(b["value"] / 1e6),
                            usd=ctx.prices.usd(CHAIN, TRON_ZERO, b["value"], 6), recipient=b["customer"]))
        ctx.bytecode_ev(b["contract"], b["tx"], b["block"])
        ctx.stats["t5_bait"] += 1


# ---------- T-6 ----------
def load_hijacked(ctx):
    ctx.hijacked = defaultdict(set)
    for r in ctx.conn.execute("SELECT address,detail FROM evidence WHERE chain=? AND type='perm_hijack'", (CHAIN,)):
        d = json.loads(r["detail"] or "{}")
        for k in d.get("controllers") or [r["address"]]:
            ctx.hijacked[d.get("victim")].add(k)


def perms_t6(ctx, txs, tr):
    for tx in txs:
        ch = td.perm_change(tx)
        if not ch:
            continue
        ctx.stats["t6_candidates"] += 1
        if ctx.allowed_any(ch["victim"], *ch["controllers"]):
            continue
        hist = {}
        for k in ch["controllers"][:3]:
            cr = ctx.created_ts(k)
            hist[k] = None if cr is None else bool(cr and tx["ts"] - cr > 86400)
        sig = td.perm_signal(ch, ctx.created_ts(ch["victim"]) or None, tx["ts"], hist)
        if not sig:
            continue
        ctrl = ch["controllers"][0]
        ctx.emit("perm_hijack", ctrl, tx["h"], tx["block"], sig)
        for k in ch["controllers"]:
            ctx.hijacked.setdefault(ch["victim"], set()).add(k)
        ctx.stats["t6_hijack"] += 1
    if not ctx.hijacked:
        return
    legs = defaultdict(list)
    for t in tr:
        legs[t["tx"]].append(t)
    for tx in txs:
        ctrls = ctx.hijacked.get(tx["frm"])
        if not ctrls or not tx["ok"] or tx["type"] not in ("TransferContract", "TriggerSmartContract"):
            continue
        out = [t for t in legs.get(tx["h"], ()) if t["frm"] == tx["frm"] and t["value"] > 0]
        if tx["type"] == "TransferContract" and tx["amount"] <= 0 or tx["type"] == "TriggerSmartContract" and not out:
            continue
        signer = signer_of(tx)
        if signer not in ctrls:
            continue
        det = dict(victim=tx["frm"], signer=signer, to=tx["to"], amount_trx=tx["amount"] / 1e6 if tx["amount"] else None,
                   tokens=sorted({t["token"] for t in out}))
        ctx.emit("perm_hijack_drain", signer, tx["h"], tx["block"], det)
        if tx["type"] == "TransferContract":
            ctx.pdr.append(dict(tx=tx["h"], li=-1, block=tx["block"], victim=tx["frm"], drainer=signer, token=TRON_ZERO,
                                symbol="TRX", decimals=6, amount=str(tx["amount"] / 1e6),
                                usd=ctx.prices.usd(CHAIN, TRON_ZERO, tx["amount"], 6), recipient=tx["to"]))
        else:
            ctx.tokens.ensure({t["token"] for t in out})
            ctx.pdr += [ctx.drain_row(t, tx["frm"], signer) for t in out]
        ctx.stats["t6_drain"] += 1


# ---------- T-7 ----------
def fees_t7(ctx, pulls, txs, last_ts):
    window = list(ctx.ptx.values())
    recent = [p for p in ctx.tr_carry if last_ts - p["ts"] <= TRON_FEE_WINDOW]
    cands = {(p["tx"], p["li"]): p for p in recent + pulls}
    for f in td.fixed_fees(list(cands.values()), window):
        if ctx.allowed_any(f["fee_to"]) or labelled(ctx, f["fee_to"]):
            continue
        vi = ctx.cinfo(f["victim"])
        if vi is None or vi["is_contract"]:
            continue                      # pulls out of pools / vaults are not victims
        ctx.emit("fixed_fee", f["fee_to"], f["fee_tx"], f["block"],
                 dict(amount_trx=f["amount"] // 1_000_000, caller=f["caller"], victim=f["victim"], pull_tx=f["pull_tx"]))
        ctx.stats["t7_fee"] += 1


# ---------- T-8 ----------
def poison_t8(ctx, tr):
    for subject, legs in td.zero_transfers(tr, ctx.ptx, {TRON_USDT}).items():
        if len(legs) < TRON_POISON_MIN or ctx.allowed_any(subject):
            continue
        ctx.emit("zero_transfer_spoof", subject, legs[0]["tx"], legs[0]["block"],
                 dict(legs=len(legs), victims=len({x["frm"] for x in legs}), spoof=True,
                      sample=[dict(victim=x["frm"], lookalike=x["to"]) for x in legs[:3]]))
        ctx.stats["t8_poison"] += 1


# ---------- driver ----------
def scan_tron(conn, seeds, labels, prices, max_blocks=None, deadline=None, rpc=None, start=None, end=None,
              persist_cursor=True, chunk=None):
    cfg = CHAINS[CHAIN]
    rpc = rpc or TronRpc()
    deadline = deadline or (time.monotonic() + 600)
    ctx = TronCtx(conn, rpc, seeds, labels, prices, deadline)
    head = rpc.block_number()
    keyless = bool(getattr(rpc, "keyless", False))
    meta_set(conn, f"keyless:{CHAIN}", int(keyless))
    if start is None:
        mb = max_blocks or cfg["max_blocks"]
        if keyless:
            mb = min(mb, cfg.get("max_blocks_keyless", mb))      # ~300 credits/s per IP without a key
        start, end = plan_range(conn, CHAIN, head, mb)
    meta_set(conn, f"head:{CHAIN}", head)
    if persist_cursor and not meta_get(conn, f"cursor:{CHAIN}"):
        meta_set(conn, f"cursor:{CHAIN}", start - 1)     # the chain is listed (with its lag) even if nothing was fetched
    st = ctx.stats
    st["head"], st["start"] = head, start
    done = start - 1
    t0 = time.monotonic()
    if end >= start:
        load_state(ctx)
        load_hijacked(ctx)
        try:
            ctx.fetch_seed_codes()
        except Exception as e:  # noqa: BLE001
            log.warning("tron: seed code fetch failed: %s", e)
        size = chunk or cfg["chunk"]
        a = start
        while a <= end and time.monotonic() < deadline:
            hi = min(end, a + size - 1)
            tf = time.monotonic()
            try:
                blocks = rpc.blocks(a, hi)
                infos = rpc.tx_infos([int(b["block_header"]["raw_data"].get("number", 0)) for b in blocks], deadline=deadline)
            except HttpError as e:
                log.warning("tron: blocks %s-%s unavailable (%s); stopping this run", a, hi, e)
                break
            missing = [int(b["block_header"]["raw_data"].get("number", 0)) for b in blocks
                       if infos.get(int(b["block_header"]["raw_data"].get("number", 0))) is None]
            if missing:                       # never advance the cursor past a block whose logs were not fetched
                first = min(missing)
                st["info_missing"] += len(missing)
                blocks = [b for b in blocks if int(b["block_header"]["raw_data"].get("number", 0)) < first]
                infos = {n: v for n, v in infos.items() if n < first}
                hi = first - 1
                log.warning("tron: tx info of block %s unavailable (credit limit / time budget); stopping this run at %s",
                            first, hi)
            if not blocks:
                break
            t1 = time.monotonic()
            process_tron_chunk(ctx, blocks, infos)
            log.info("tron: blocks %s-%s: fetch %.1fs, detect %.1fs, txs %d, pull legs %d, contract lookups %d, "
                     "account lookups %d", a, hi, t1 - tf, time.monotonic() - t1, st["txs"], st["pull_legs"],
                     st["contract_lookups"], st["account_lookups"])
            done = hi
            if persist_cursor:
                meta_set(conn, f"cursor:{CHAIN}", done)
                meta_set(conn, f"scan_at:{CHAIN}", now_ts())
                conn.commit()
            a = hi + 1
            if missing:
                break
    if persist_cursor:
        meta_set(conn, f"scan_at:{CHAIN}", now_ts())
    conn.commit()
    st["end"], st["done"] = end, done
    st["blocks"] = max(0, done - start + 1)
    st["lag"] = max(0, head - done)
    st["rpc_calls"], st["rpc_limit_hits"], st["rpc_errors"] = rpc.calls, rpc.limit_hits, rpc.errors
    st["source"] = "trongrid"
    st["mb"] = round(getattr(rpc, "bytes", 0) / 1e6, 1)
    st["sec"] = round(time.monotonic() - t0, 1)
    return st
