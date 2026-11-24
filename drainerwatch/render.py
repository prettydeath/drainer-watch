"""site/data.json + site/index.html and CSV exports.

site/index.html is the built web app (web/dist, it fetches data.json) when it is present, else
drainerwatch/template.html with the data embedded (fallback for a local render without Node)."""
import csv
import json
import logging
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

from . import exposure, famname, freeze
from .constants import CHAINS, DATA_DIR, ROOT, SITE_DIR, TEMPLATE
from .scan import load_gaps
from .db import meta_get
from .util import iso, now_ts

log = logging.getLogger("drainerwatch.render")
PLACEHOLDER = "/*__DATA__*/null"
WEB_DIST = ROOT / "web" / "dist"
TIER_ORDER = {"T1": 0, "T2": 1, "T3": 2}
MAX_CONTRACTS, MAX_DRAINS, MAX_EVIDENCE, MAX_LINKS = 2000, 500, 20, 50


def _strip(s):
    return re.sub(r'"generated_at":\s*"[^"]*"', '"generated_at":""', s)


def write_if_changed(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and _strip(path.read_text(encoding="utf-8")) == _strip(text):
        return False
    path.write_text(text, encoding="utf-8")
    return True


def describe(type_, d):
    """Human-readable evidence line."""
    if type_ == "seed_activity":
        return f"{d.get('kind')} from victim {d.get('victim')} (token {d.get('token')}) to a seed address"
    if type_ == "split_pull":
        rc = ", ".join(f"{r['wallet']} {r['share']:.0%} ({r['role']})" for r in d.get("recipients", []))
        return f"one tx pulled {d.get('token')} from {len(d.get('victims', []))} victim(s) and split it: {rc}"
    if type_ == "multi_victim_pull":
        return f"pulled tokens from {len(d.get('victims', []))} approving wallet(s) in one tx"
    if type_ == "pays_known_operator":
        return f"token transfer to known operator/payout wallet {d.get('wallet')}"
    if type_ == "bytecode":
        bits = []
        if d.get("redflags"):
            bits.append("red-flag selectors " + ", ".join(d["redflags"]))
        if d.get("family"):
            bits.append(f"family {d['family']} ({d.get('via')}) matches seed {d.get('matched_seed')}")
        if d.get("kit"):
            bits.append(f"kit selector fingerprint {d['kit']}")
        if d.get("owner_gated_puller"):
            bits.append("owner-gated parametric transferFrom puller (CALLER==SLOAD check, no hard-coded address)")
        if d.get("kit_exact"):
            bits.append(f"exact runtime of the MS Contract Generator bait {d['kit_exact']}")
        if d.get("ms_variant"):
            bits.append(f"MS bait variant {d['ms_variant']}")
        if d.get("kit_public"):
            bits.append(f"exact runtime of the kit public contract {d['kit_public']}")
        return "; ".join(bits) or "bytecode analysis"
    if type_ == "eip7702_sweeper":
        return f"EIP-7702 delegate: {d.get('authorizations')} authorization(s); {d.get('reason')}"
    if type_ == "redflag_payable":
        return f"payable call {d.get('name')} with {d.get('value_wei')} wei (native forwarding not visible without traces)"
    if type_ == "eoa_spender_pull":
        return (f"EOA spender pulled {d.get('token')} from victim {d.get('victim')} to {d.get('recipient')} "
                f"(via {d.get('via')})")
    if type_ == "approval_fingerprint":
        return (f"victim {d.get('victim')} approved token {d.get('token')} with the {d.get('kit')} kit amount "
                f"(hard-coded approval value: kit fingerprint)")
    if type_ == "bait_payable":
        if d.get("kit") == "ms_new":
            return (f"victim {d.get('victim')} paid {d.get('value_wei')} wei to MS_NEW {d.get('name')}: handler (customer) "
                    f"{d.get('customer')}, keeper (worker) {d.get('worker')}, depositer {d.get('depositer')}, "
                    f"percent {d.get('percent')}" + ("; is_cashback = 1 (1 wei back to the sender)" if d.get("cashback") else "")
                    + ("; kit public contract" if d.get("public") else ""))
        if d.get("kit") == "ms_generated":
            fee = (f", {d.get('fee_percent')}% to {d.get('fee_receiver')}" if d.get("fee_percent") else "")
            fresh = (f"; created {d.get('created_sec_before')} s before" if d.get("created_sec_before") is not None else "")
            return (f"victim {d.get('victim')} paid {d.get('value_wei')} wei to generated bait {d.get('name')}: main "
                    f"receiver (customer) {d.get('customer')}{fee}{fresh}; use #{d.get('uses')}")
        pt = ("; pass-through variant: the argument received msg.value in the same tx"
              + {True: " (contract balance unchanged)", False: " (contract balance changed)"}.get(d.get("balance_neutral"), "")
              if d.get("passthrough") else "")
        tv = ("; Trusty v1 pass-through (the argument receives msg.value minus a 5-10 % owner fee)"
              + ("; kit public contract" if d.get("public") else "") if d.get("kit") == "trusty_v1" else "")
        if d.get("unit") == "sun":
            shp = {True: "; amount = min(balance - 50 TRX, 80 % of balance) (Claimer shape)", False: "",
                   None: ""}.get(d.get("claimer_shape"), "")
            return (f"victim {d.get('victim')} paid {int(d.get('value_wei') or 0) / 1e6:g} TRX to bait function "
                    f"{d.get('name')}; argument = payout wallet {d.get('customer')}{shp}")
        return (f"victim {d.get('victim')} paid {d.get('value_wei')} wei to bait function {d.get('name')}; "
                f"argument = customer payout wallet {d.get('customer')}{pt}{tv}")
    if type_ == "kit_deposit":
        share = f"{d['balance_share']:.0%} of its balance" if d.get("balance_share") else "balance not checked"
        return (f"fresh EOA {d.get('depositer')} (nonce {d.get('nonce')}) called MS_NEW Deposit with gasLimit "
                f"{d.get('gas_limit')} and {d.get('value_wei')} wei ({share}): Wallet Randomizer native leg")
    if type_ == "gen_back_transfer":
        return (f"deployer {d.get('deployer')} sent its leftover {d.get('value_wei')} wei to {d.get('wallet')} after "
                f"deploying this generated bait (kit 'back' transfer)")
    if type_ == "ms_deadline":
        vals = ", ".join(f"{k}={v}" for k, v in (d.get("values") or {}).items())
        pulled = "; tokens pulled from the owner in the same chunk" if d.get("pulled") else ""
        return (f"{d.get('kind')} submitted by {d.get('submitter')} for owner {d.get('victim')} with a millisecond "
                f"deadline ({vals}){pulled}")
    if type_ == "oneshot_spender":
        how = " and ".join(x for x in ("funded it" if d.get("fund_tx") else "",
                                        "received its leftover with gas 25 200 / 30 000" if d.get("return_tx") else "") if x)
        return (f"one-shot EOA {d.get('worker')} (nonce {d.get('worker_nonce')}) pulled {d.get('token')} from "
                f"{d.get('victim')} to {d.get('recipient')}; this hub {how}")
    if type_ == "kit_router_swap" and d.get("xtx"):
        return (f"victim {d.get('victim')} gave a legitimate router the kit allowance (tx {d.get('approval_tx')}) and "
                f"{d.get('approval_sec_before')} s later signed a zero-minimum swap paying this EOA")
    if type_ == "dust_approve":
        return (f"{d.get('victim')} sent {d.get('fn')} for this spender with {d.get('value_wei')} wei attached"
                + (f" and the {d.get('kit')} kit amount" if d.get("kit") else "") + " (kit quirk)")
    if type_ == "emergency_gas":
        who = "this wallet" if d.get("spender_is_funder") else f"flagged spender {d.get('spender')}"
        return (f"sent {d.get('value_wei')} wei of gas to {d.get('victim')} (tx {d.get('fund_tx')}), which then approved "
                f"{who} within 30 min" + (f" with the {d.get('kit')} kit amount" if d.get("kit") else ""))
    if type_ in ("batch_approval_drain", "kit_router_swap"):
        what = ("batch of approvals (kit amount / max)" if type_ == "batch_approval_drain"
                else "kit-amount approval to a legitimate router")
        return (f"victim {d.get('victim')} signed a {what} and in the same tx its tokens went to this EOA "
                f"({len(d.get('legs') or [])} leg(s)); nothing came back to the victim")
    if type_ == "owner_collect":
        return (f"owner-collector contract pulled {d.get('token')} from {d.get('victim')} to its caller/owner "
                f"{d.get('collector')} ({d.get('kit')})")
    if type_ == "cross_chain":
        return (f"same address and opcode skeleton on {d.get('linked_chain')}"
                + (f" (flagged {d.get('linked_tier')} there)" if d.get("linked_tier") else ""))
    if type_ == "bait_withdraw":
        return f"customer {d.get('customer')} called {d.get('name')} on the bait contract (to {d.get('withdraw_to')})"
    if type_ == "split_xtx":
        rc = ", ".join(f"{r['wallet']} {r['share']:.0%} ({r['role']})" for r in d.get("recipients", []))
        return (f"caller {d.get('caller')} pulled {d.get('token')} from victim {', '.join(d.get('victims', []))} in "
                f"{len(d.get('txs', []))} txs within 60 s and split it: {rc}")
    # TRON rules T-1..T-8
    if type_ == "kit_pull":
        who = "its creator" if d.get("caller_is_creator") else "caller"
        return (f"{who} {d.get('caller')} pulled {d.get('token')} from {d.get('victim')} to {d.get('recipient')} through "
                f"this contract ({d.get('kit')} dispatcher: token, from, to and amount are call parameters)")
    if type_ == "tron_approval":
        what = {"kit_amount": "approved the kit amount 10^46", "approve_all": "called daea85c5(address) ('ApproveAll')",
                "aml_exact": "approved its exact balance with feeLimit 300 TRX and then sent this spender a bait transfer",
                "increase_max": "called increaseApproval with 2^256-1"}.get(d.get("kind"), d.get("kind"))
        extra = (" (fresh account)" if d.get("fresh_spender") else "") + (
            f" (spender code: {d.get('spender_kit')})" if d.get("spender_kit") else "")
        return f"victim {d.get('victim')} {what} for this spender on {d.get('token')}, feeLimit {d.get('fee_limit_trx')} TRX{extra}"
    if type_ == "prefund_approve":
        rel = "this wallet" if not d.get("spender_creator") else f"{d.get('spender')}, a contract this wallet created"
        return (f"sent {d.get('amount_trx')} TRX to {d.get('victim')} (tx {d.get('fund_tx')}), which {d.get('sec_before')} s "
                f"later approved {rel}: gas pre-funding before the approval")
    if type_ == "perm_hijack":
        lost = " and ".join(x for x in ("owner" if d.get("owner_lost") else "", "active" if d.get("active_lost") else "") if x)
        return (f"account {d.get('victim')} ({d.get('age_days')} days old) changed its {lost} permission so that its own key "
                f"is no longer enough; controller keys {', '.join(d.get('controllers') or [])}"
                + (f"; without history: {', '.join(d['fresh_keys'])}" if d.get("fresh_keys") else ""))
    if type_ == "perm_hijack_drain":
        return (f"outflow from hijacked account {d.get('victim')} signed by this controller key"
                + (f": {d.get('amount_trx')} TRX" if d.get("amount_trx") else "")
                + (f"; tokens {', '.join(d.get('tokens') or [])}" if d.get("tokens") else ""))
    if type_ == "fixed_fee":
        return (f"received a fixed {d.get('amount_trx')} TRX from {d.get('caller')} within 60 s of its pull from "
                f"{d.get('victim')} (pull tx {d.get('pull_tx')})")
    if type_ == "zero_transfer_spoof":
        return f"{d.get('legs')} zero-value USDT transferFrom legs from {d.get('victims')} wallet(s) in one chunk (address poisoning)"
    # web-research rules W1-W10
    if type_ == "vanity_approval":
        return f"{d.get('victim')} approved this vanity-address spender ({d.get('kind')}) on {d.get('token')}"
    if type_ == "deploy_drain":
        if d.get("role") == "factory":
            return (f"this contract's tx created {d.get('child')}, which used a permit of {', '.join(d.get('victims') or [])} "
                    f"and moved its tokens in the same tx")
        if d.get("via") == "factory":
            return (f"created inside the tx (by {d.get('factory')}; check: {d.get('created_check')}) and in that tx used a "
                    f"permit of {', '.join(d.get('victims') or [])} to move its tokens")
        return (f"deployed by {d.get('deployer')} in a tx that moved tokens of {', '.join(d.get('victims') or [])} "
                f"(deploy-and-drain in one tx)")
    if type_ == "ghost_forward":
        return (f"tokens left {d.get('ghost')}, an address that has no code and never sent a tx, in a tx through this "
                f"contract (code that existed only inside the tx: pre-computed address deployed, forwarded, destroyed)")
    if type_ == "bait_forward":
        kept = f"; {d['kept_share']:.0%} kept by the contract" if d.get("kept_share") else ""
        return (f"victim {d.get('victim')} paid {d.get('value_wei')} wei (selector 0x{d.get('selector') or ''}"
                f"{'' if d.get('in_dispatch') else ', caught by the fallback'}); {d.get('forwarded_share', 0):.0%} left to "
                f"third addresses in the same tx ({d.get('via')}){kept}")
    if type_ == "token_spender_pull":
        return (f"ERC-20-like contract with DELEGATECALL pulled {d.get('token')} from {d.get('victim')} (its approver) to "
                f"{d.get('recipient')}; called by {d.get('caller')}")
    if type_ == "owner_takeover":
        return (f"became owner of {d.get('contract')} ({d.get('kind')}, tx {d.get('change_tx')} signed by {d.get('signer')}) "
                f"and then moved tokens out of it (new owner nonce {d.get('new_owner_nonce')})")
    if type_ == "safe_approval":
        return f"{d.get('victim')} approved this Safe proxy ({d.get('kind')}) on {d.get('token')}"
    if type_ == "safe_pull":
        return f"this Safe proxy pulled {d.get('token')} from {d.get('victim')} to {d.get('recipient')}"
    if type_ == "seaport_zero":
        return (f"filled a Seaport order of {d.get('victim')} for {d.get('n_nfts')} NFT(s) while the offerer received "
                f"nothing (zero-price listing)")
    if type_ == "nft_operator_pull":
        return (f"{d.get('victim')} set this EOA as operator for all its NFTs (tx {d.get('approval_tx')}); it then moved "
                f"{d.get('n_nfts')} NFT(s) of that wallet")
    if type_ == "batch7702_approve":
        via = d.get("legit_delegate") or d.get("delegate")
        return (f"{d.get('victim')} sent a batch to itself through its EIP-7702 account ({via}) that approved this EOA "
                f"and moved tokens out; nothing came back")
    if type_ == "eip7702_batch":
        return (f"{d.get('max_per_tx')} authorizations to this delegate in one tx ({d.get('authorizations')} in "
                f"{d.get('txs')} tx(s), {d.get('chain0')} with chainId 0): mass delegation of many keys")
    if type_ == "poison_zero":
        return (f"{d.get('legs')} zero-value stablecoin transferFrom legs out of {d.get('victims')} wallet(s) in one chunk, "
                f"{d.get('lookalikes')} to lookalikes of their recent counterparties (address poisoning)")
    if type_ == "foreign_recipient_swap":
        kit = "; deadline = block time + ~99 990 s (MS Drainer kit)" if d.get("kit") else ""
        return (f"victim {d.get('victim')} signed {d.get('fn')} on {d.get('router')} selling {d.get('amount_in')} of "
                f"{d.get('token')} with amountOutMin 0, paying this EOA{kit}")
    return json.dumps(d, sort_keys=True)


def _num(x):
    return round(x or 0, 2)


def build_payload(conn, now=None):
    now = now or now_ts()
    d24, d7 = now - 86400, now - 7 * 86400
    chains = {}
    for ch, cfg in CHAINS.items():
        cur = meta_get(conn, f"cursor:{ch}")
        if cur is None:
            continue
        head = int(meta_get(conn, f"head:{ch}", cur) or cur)
        sc = meta_get(conn, f"scan_at:{ch}")
        gaps = load_gaps(conn, ch)
        chains[ch] = dict(cursor_block=int(cur), head_block=head, lag_blocks=max(0, head - int(cur)),
                          last_scan_at=iso(int(sc)) if sc else "", explorer=cfg["explorer"],
                          tx_path=cfg.get("tx_path", "tx"), native=cfg.get("native"), block_sec=cfg.get("block_sec"),
                          gaps=[dict(g, at=iso(g.get("at"))) for g in gaps[-20:]],
                          gap_blocks=sum(max(0, int(g["to"]) - int(g["from"]) + 1) for g in gaps))
        if meta_get(conn, f"keyless:{ch}") == "1":
            chains[ch]["note"] = "TronGrid without an API key: reduced block coverage per run"

    crow = conn.execute("SELECT * FROM contracts").fetchall()
    crow.sort(key=lambda r: (TIER_ORDER.get(r["tier"], 9), -(parse(r["last_seen"]))))
    tiers = Counter(r["tier"] for r in crow)
    crow = crow[:MAX_CONTRACTS]

    pay = defaultdict(list)
    for r in conn.execute("SELECT chain,drainer,wallet,role,share,txs FROM payouts ORDER BY share DESC"):
        pay[(r["chain"], r["drainer"])].append(dict(wallet=r["wallet"], role=r["role"], share=round(r["share"] or 0, 4),
                                                    txs=r["txs"]))
    ev = defaultdict(list)
    for r in conn.execute("SELECT chain,address,type,tx,ts,detail FROM evidence ORDER BY ts DESC"):
        k = (r["chain"], r["address"])
        if len(ev[k]) < MAX_EVIDENCE:
            ev[k].append(dict(type=r["type"], tx=r["tx"], ts=iso(r["ts"]) or "", detail=describe(
                r["type"], json.loads(r["detail"] or "{}"))))
    dep = {(r["chain"], r["address"]): dict(r) for r in conn.execute("SELECT * FROM contract_deployer")}
    info = {(r["chain"], r["address"]): dict(r) for r in conn.execute("SELECT * FROM deployer_info")}
    labels = {(r["chain"], r["address"]): r["entity"] for r in conn.execute("SELECT chain,address,entity FROM labels")}
    dep_count = Counter((r["chain"], r["deployer"]) for r in dep.values() if r["deployer"])
    links_by_subject = defaultdict(list)
    for r in conn.execute("SELECT * FROM vasp_links ORDER BY ts DESC"):
        links_by_subject[(r["chain"], r["subject"])].append(r)

    # K14: the same address flagged on other chains with the same skeleton (or linked by cross_chain evidence)
    skel = {(r["chain"], r["address"]): r["skeleton"] for r in conn.execute("SELECT chain,address,skeleton FROM codes")}
    by_addr = defaultdict(list)
    for r in crow:
        by_addr[r["address"]].append(r)
    twins = {}
    for addr, rs in by_addr.items():
        for r in rs:
            sk = skel.get((r["chain"], addr))
            tw = [dict(chain=o["chain"], tier=o["tier"]) for o in rs
                  if o["chain"] != r["chain"] and sk and skel.get((o["chain"], addr)) == sk]
            if tw:
                twins[(r["chain"], addr)] = tw

    contracts = []
    for r in crow:
        k = (r["chain"], r["address"])
        d = dep.get(k)
        di = info.get((r["chain"], d["deployer"])) if d and d["deployer"] else None
        deployer = dict(address=d["deployer"] if d else None, tx=d["tx"] if d else None,
                        via=(d["via"] if d else "unknown"), factory=d["factory"] if d else None, block=d.get("block") if d else None,
                        funder=di["funder"] if di else None,
                        funder_entity=labels.get((r["chain"], di["funder"])) if di and di["funder"] else None,
                        funder_tx=di["funder_tx"] if di else None,
                        other_contracts=max(0, dep_count[(r["chain"], d["deployer"])] - 1) if d and d["deployer"] else 0)
        subjects = [r["address"]] + [p["wallet"] for p in pay.get(k, [])] + ([d["deployer"]] if d and d["deployer"] else [])
        vl = []
        for s in dict.fromkeys(subjects):
            for l in links_by_subject.get((r["chain"], s), []):
                vl.append(dict(subject=l["subject"], role=l["subject_role"], counterparty=l["counterparty"],
                               kind=l["kind"], entity=l["entity"], category=l["category"], tx=l["tx"],
                               tx_in=l["tx_in"], ts=iso(l["ts"]) or "", amount=l["amount"], symbol=l["symbol"],
                               usd=l["usd"], confidence=l["confidence"]))
        vl = vl[:MAX_LINKS]
        contracts.append(dict(chain=r["chain"], address=r["address"], tier=r["tier"], score=r["score"], source=r["source"],
                              family=r["family"], labels=json.loads(r["labels"] or "[]"), first_seen=r["first_seen"] or "",
                              last_seen=r["last_seen"] or "", victims=r["victims"], drains=r["drains"], usd=_num(r["usd"]),
                              code_size=r["code_size"], verified=None if r["verified"] is None else bool(r["verified"]),
                              contract_name=r["contract_name"] if "contract_name" in r.keys() else None,
                              payouts=pay.get(k, []), deployer=deployer, vasp_links=vl, evidence=ev.get(k, []),
                              is_contract=None if r["is_contract"] is None else bool(r["is_contract"]),
                              cluster=r["cluster"] if "cluster" in r.keys() else None,
                              cross_chain=twins.get(k, [])))

    drains = [dict(chain=r["chain"], tx=r["tx"], ts=iso(r["ts"]) or "", victim=r["victim"], drainer=r["drainer"],
                   token=r["token"], symbol=r["symbol"], amount=r["amount"], usd=r["usd"], recipient=r["recipient"])
              for r in conn.execute("SELECT * FROM drains ORDER BY ts DESC, tx DESC LIMIT ?", (MAX_DRAINS,))]

    # headline totals count only drains attributed to T1/T2 subjects; T3 leads (e.g. custodial sweeps) stay out
    strong = ("FROM drains d JOIN contracts c ON c.chain=d.chain AND c.address=d.drainer "
              "AND c.tier IN ('T1','T2') WHERE d.ts>=?")
    t = conn.execute("SELECT COUNT(DISTINCT d.victim) v, COALESCE(SUM(d.usd),0) u, COUNT(*) n " + strong,
                     (d24,)).fetchone()
    u7 = conn.execute("SELECT COALESCE(SUM(d.usd),0) u " + strong, (d7,)).fetchone()["u"]
    n_all = conn.execute("SELECT COUNT(*) n FROM drains WHERE ts>=?", (d24,)).fetchone()["n"]
    totals = dict(tiers={k: tiers.get(k, 0) for k in ("T1", "T2", "T3")}, victims_24h=t["v"], usd_24h=_num(t["u"]),
                  usd_7d=_num(u7), drains_24h=t["n"], drains_24h_all=n_all)

    ops = []
    for r in conn.execute(
            "SELECT p.chain,p.wallet,COUNT(DISTINCT p.drainer) dr,SUM(p.role='affiliate') aff FROM payouts p "
            "JOIN contracts c ON c.chain=p.chain AND c.address=p.drainer GROUP BY p.chain,p.wallet"):
        u = conn.execute("SELECT COALESCE(SUM(usd),0) u FROM drains WHERE chain=? AND recipient=?",
                         (r["chain"], r["wallet"])).fetchone()["u"]
        ops.append(dict(chain=r["chain"], wallet=r["wallet"], drainers=r["dr"], affiliates=r["aff"] or 0, usd=_num(u)))
    ops.sort(key=lambda o: (-o["usd"], -o["drainers"]))

    allow_rows, pulled, exposure_total = exposure.payload(conn)
    for c in contracts:
        k = (c["chain"], c["address"])
        c["open_allowances"] = allow_rows.get(k, [])
        c["pulled"] = bool(pulled.get(k)) or c["drains"] > 0
    fnames = famname.names_for(conn, contracts)          # family_name / family_name_source (caches only)
    for c in contracts:
        c["family_name"], c["family_name_source"] = fnames.get(c["family"], (None, None)) if c["family"] else (None, None)
    fam = defaultdict(lambda: dict(members=0, seed_members=0, chains=set()))
    for c in contracts:
        if c["family"]:
            f = fam[c["family"]]
            f["members"] += 1
            f["seed_members"] += 1 if "seed" in c["labels"] else 0
            f["chains"].add(c["chain"])
    families = [dict(family=k, family_name=fnames.get(k, (None, None))[0], family_name_source=fnames.get(k, (None, None))[1],
                     members=v["members"], seed_members=v["seed_members"], chains=sorted(v["chains"]))
                for k, v in sorted(fam.items(), key=lambda kv: -kv[1]["members"])]

    dgroups = defaultdict(lambda: dict(contracts=0))
    for c in contracts:
        a = c["deployer"]["address"]
        if a:
            g = dgroups[(c["chain"], a)]
            g["contracts"] += 1
            g["funder_entity"] = c["deployer"]["funder_entity"]
    deployers = [dict(chain=k[0], address=k[1], contracts=v["contracts"], funder_entity=v.get("funder_entity"))
                 for k, v in sorted(dgroups.items(), key=lambda kv: -kv[1]["contracts"])]

    vg = defaultdict(lambda: dict(cat=Counter(), links=0, usd=0.0, subjects=set(), dep=[], chains=set()))
    for r in conn.execute("SELECT * FROM vasp_links"):
        g = vg[r["entity"] or "unknown"]
        g["cat"][r["category"]] += 1
        g["links"] += 1
        g["usd"] += r["usd"] or 0
        g["subjects"].add((r["chain"], r["subject"]))
        g["chains"].add(r["chain"])
        if r["kind"] == "deposit_sweep" and r["counterparty"] not in g["dep"]:
            g["dep"].append(r["counterparty"])
    vasps = [dict(entity=k, category=v["cat"].most_common(1)[0][0], links=v["links"], usd=_num(v["usd"]),
                  subjects=len(v["subjects"]), deposit_addresses=v["dep"][:50], chains=sorted(v["chains"]))
             for k, v in sorted(vg.items(), key=lambda kv: (-kv[1]["usd"], -kv[1]["links"]))]

    daily = defaultdict(lambda: dict(usd=0.0, victims=set(), new_contracts=0))
    for r in conn.execute("SELECT date(ts,'unixepoch') d,victim,usd FROM drains WHERE ts>=?", (now - 30 * 86400,)):
        g = daily[r["d"]]
        g["usd"] += r["usd"] or 0
        g["victims"].add(r["victim"])
    for c in contracts:
        if c["first_seen"] and parse(c["first_seen"]) >= now - 30 * 86400:
            daily[c["first_seen"][:10]]["new_contracts"] += 1
    days = [dict(date=k, usd=_num(v["usd"]), victims=len(v["victims"]), new_contracts=v["new_contracts"])
            for k, v in sorted(daily.items())]

    cl = defaultdict(lambda: dict(chain=None, members=[], tiers=Counter(), shared=set()))
    for c in contracts:
        if c.get("cluster"):
            g = cl[c["cluster"]]
            g["chain"] = c["chain"]
            g["members"].append(c["address"])
            g["tiers"][c["tier"]] += 1
    if cl:
        mem = {(g["chain"], a): cid for cid, g in cl.items() for a in g["members"]}
        wd = defaultdict(set)
        for r in conn.execute("SELECT chain,drainer,wallet FROM payouts"):
            if (r["chain"], r["drainer"]) in mem:
                wd[(r["chain"], r["wallet"], mem[(r["chain"], r["drainer"])])].add(r["drainer"])
        for (ch, w, cid), ds in wd.items():
            if len(ds) >= 2:
                cl[cid]["shared"].add(w)
    clusters = [dict(cluster=cid, chain=g["chain"], members=sorted(g["members"]), shared_wallets=sorted(g["shared"]),
                     max_tier=min(g["tiers"], key=lambda t: TIER_ORDER.get(t, 9)), tiers=dict(g["tiers"]))
                for cid, g in sorted(cl.items(), key=lambda kv: -len(kv[1]["members"]))]

    frz, frz_total = freeze.payload(conn)
    return dict(generated_at=iso(now), chains=chains, totals=totals, contracts=contracts, drains=drains, operators=ops[:200],
                families=families, deployers=deployers, vasps=vasps, daily=days, clusters=clusters,
                freezable=frz, freezable_total=frz_total, exposure_total_usd=exposure_total)


def parse(s):
    from .util import parse_iso
    return parse_iso(s) or 0


def embed(template: str, payload: dict) -> str:
    """Replace the literal placeholder with JSON; '</' is escaped so data can never close a <script>."""
    js = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    js = js.replace("</", "<\\/").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return template.replace(PLACEHOLDER, js)


def export_csv(conn, data_dir=DATA_DIR):
    data_dir.mkdir(parents=True, exist_ok=True)
    for name, q in (("contracts.csv", "SELECT * FROM contracts ORDER BY tier,last_seen DESC"),
                    ("drains.csv", "SELECT * FROM drains ORDER BY ts DESC")):
        rows = conn.execute(q).fetchall()
        if not rows:
            continue
        with open(data_dir / name, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(rows[0].keys())
            w.writerows([tuple(r) for r in rows])


def copy_app(dist: Path, site_dir: Path):
    """Copy the built web app (web/dist) into site/; it loads data.json at runtime. data.json itself is never copied."""
    for f in dist.rglob("*"):
        if f.is_file() and f.name != "data.json":
            out = site_dir / f.relative_to(dist)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, out)


def render_all(conn, template_path=TEMPLATE, site_dir=SITE_DIR, data_dir=DATA_DIR, now=None, web_dist=None):
    payload = build_payload(conn, now)
    site_dir.mkdir(parents=True, exist_ok=True)
    write_if_changed(site_dir / "data.json", json.dumps(payload, ensure_ascii=False, indent=1))
    template_path = Path(template_path)
    if web_dist and (Path(web_dist) / "index.html").exists():
        copy_app(Path(web_dist), site_dir)
    elif template_path.exists():
        html = embed(template_path.read_text(encoding="utf-8"), payload)
        write_if_changed(site_dir / "index.html", html)
    else:
        log.warning("template.html missing: wrote data.json only")
    export_csv(conn, data_dir)
    return payload
