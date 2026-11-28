"""Final tier policy, from the measured precision audit of the live site (2026-11-28, 189 labelled subjects).

The detector labels still say WHAT was seen; this policy decides how much each one is worth. It only ever LOWERS the
tier rollup computed (never raises it), runs on every roll-up over the whole evidence table, so a change here re-tiers
every stored subject, not only new finds.

  * Poisoning: address-poisoning evidence (spoof splits, counterfeit / tiny / zero-value poison transfers) or the
    poisoner contract shape -> category `poisoning`, tier T3: out of T1/T2 and out of the drain / USD totals.
  * T1 needs own proof: a kit fingerprint (STRONG, measured 98-100 % precision), or drainer code (codeclass) with at
    least one observed pull from a third party.
  * legit_code (codeclass) caps at T3, unless a kit fingerprint is present (kit evidence wins).
  * service shapes (deposit sweeps, gasless relayers, payment fan-out) cap at T3 unless a kit fingerprint is present.
  * WEAK labels (measured zero or near-zero precision) are T3-only signals: the tier is recomputed without them, so they
    never lift a tier alone or in combination with each other.
  * T2 otherwise from the remaining labels (rollup's own rules, capped at T2), with two rescues of measured TP classes:
    TRON permission hijacks whose post-change recipient is a collector shared by >= 2 hijacking keys (a crew), and EOA
    approval spenders that pass a victim-harm test (one common collector, priced, non-round full-balance pulls).
"""
import json
import statistics
from collections import Counter, defaultdict

from . import codeclass
from .detectors import assign_tier

RANK = {"T1": 1, "T2": 2, "T3": 3}
# kit fingerprints: allowed to keep T1 (and win over legit_code / service shapes)
STRONG = {"kit_pull", "kit_signature", "redflag_selectors", "increase_max", "approval_fingerprint", "seed",
          "oneshot_spender", "bait_payable", "bait_forward", "kit_confirmed", "ms_cashback", "dust_approve_kit",
          "emergency_gas_kit", "kit_router_swap", "oneshot_multi", "aml_approve_transfer", "foreign_swap_kit"}
# static kit labels: they need an observed pull (activity) for T1
STATIC_STRONG = {"kit_signature", "redflag_selectors"}
POISON_LABELS = {"spoof_split", "poison_counterfeit", "poison_tiny", "poison_batch", "poison_zero"}
# measured zero / near-zero precision (TP/FP on the audit): T3-only signals
WEAK = POISON_LABELS | {
    "split_pull",                                   # 1/14
    "tron_eoa_pull", "tron_eoa_pull_multi",         # 0/12, 0/8
    "prefund_approve", "prefund_approve_multi",     # 0/10, 0/9
    "tron_max_approval",                            # 0/5
    "cross_chain", "cross_chain_t1",                # 0/7, 0/1
    "multi_victim_pull",                            # 0/7
    "pays_known_operator", "pays_inferred_operator",  # 0/6, 0/6
    "ms_deadline", "ms_deadline_pull",              # 0/3
    "batch_approval_drain",                         # 0/2
    "counterfactual_forward", "counterfactual_multi",  # 0/2
    "family_match",                                 # 0/2
    "nft_bulk", "nft_bulk_multi",                   # 0/2
    "eip7702_batch", "eip7702_sweeper", "eip7702_chain0",   # 0/1 live (a poisoning delegate), FP-only in backtests
    "full_balance_pull",                            # 8/25
    "codehash_cluster",                             # 19/26 (score / cluster only)
    "perm_hijack", "perm_hijack_drain", "perm_hijack_multi",   # 10/11: only through the crew rescue below
    "eoa_spender_multi",                            # 5/5: only through the harm test below
}
# observed pulls of third-party funds (drainer code + one of these = T1); weak labels count here as observations
PULL_EVIDENCE = {"kit_pull", "split_pull", "split_xtx", "multi_victim_pull", "eoa_spender_pull", "owner_collect",
                 "oneshot_hub", "prefund_hub", "tron_contract_pull", "tron_eoa_pull", "token_spender_pull",
                 "safe_spender_pull", "full_balance_pull", "perm_hijack_drain", "deploy_drain", "router_sweep",
                 "fake_call_contract", "phish_multicall", "nft_operator_pull", "seaport_zero"}
SPLIT_SHAPE = {"split_xtx", "share_grid"}           # count only on drainer-shaped contracts (never EOAs / services)
CAP_LABELS = {"legit_code_capped", "service_shape_capped", "weak_only_capped"}
DAY = 86400


def _is_round(a):
    try:
        x = float(a)
    except (TypeError, ValueError):
        return False
    return x >= 1 and abs(x - round(x)) < 1e-9


def drain_stats(legs):
    """legs: [(ts, victim, recipient, amount, usd)] of one subject -> shape statistics."""
    n = len(legs)
    if not n:
        return None
    by_v = defaultdict(list)
    for ts, v, _, _, _ in legs:
        by_v[v].append(ts or 0)
    usd = [x[4] for x in legs if x[4]]
    rec = Counter(x[2] for x in legs)
    return dict(n=n, victims=len(by_v),
                repeat=sum(1 for ts in by_v.values() if len(ts) >= 2 and max(ts) - min(ts) > DAY),
                round=sum(_is_round(x[3]) for x in legs) / n, priced=len(usd) / n,
                med_usd=statistics.median(usd) if usd else 0.0, top=rec.most_common(1)[0][1] / n)


def service_shapes(st, contract):
    """Service shapes that a drainer does not have (measured on the audit set).
    contract: a contract never re-pulls the same victim on another day (0 of 50 audited drainer contracts did), a
    deposit sweeper does. EOA: round-amount payments swept whole (deposit sweep), tiny fixed fees (gasless relayer),
    pulls fanned out to many unrelated recipients (relayer / custodial payouts)."""
    out = set()
    if not st:
        return out
    if contract:
        if st["repeat"] >= 2:
            out.add("deposit_sweep")
        return out
    if st["n"] >= 3 and st["round"] >= 0.5:
        out.add("deposit_sweep")
    if st["n"] >= 3 and st["priced"] >= 0.8 and st["med_usd"] < 3:
        out.add("gasless")
    if st["n"] >= 5 and st["top"] < 0.3:
        out.add("payment_fanout")
    return out


def harm_ok(st):
    """EOA approval spender (eoa_spender_multi) victim-harm test: one common collector, priced value, non-round
    full-balance pulls (5 TP / 5 FP on the audit -> 5 / 0)."""
    return bool(st) and st["top"] >= 0.8 and st["priced"] >= 0.8 and st["med_usd"] >= 5 and st["round"] < 0.5


class Context:
    """Everything the policy reads, loaded once per roll-up."""

    def __init__(self, conn, per=None, verified=None, sels=None):
        self.conn = conn
        self.per = per or {}
        self.verified = verified or {}
        self.sels = sels
        if self.sels is None:
            self.sels = {(r["chain"], r["address"]): json.loads(r["selectors"] or "[]")
                         for r in conn.execute("SELECT chain,address,selectors FROM codes")}
        self.sigs = codeclass.sel_names(conn)
        self.tron = {}
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(tron_contracts)")}
            q = "SELECT address,name,puller,kit" + (",abi" if "abi" in cols else "") + " FROM tron_contracts"
            for r in conn.execute(q):
                self.tron[r["address"]] = dict(name=r["name"], puller=r["puller"], kit=r["kit"],
                                               abi=json.loads(r["abi"] or "[]") if "abi" in cols else [])
        except Exception:  # noqa: BLE001 - table missing in minimal test databases
            pass
        self.legs = defaultdict(list)
        for r in conn.execute("SELECT chain,drainer,ts,victim,recipient,amount,usd FROM drains"):
            self.legs[(r["chain"], r["drainer"])].append((r["ts"], r["victim"], r["recipient"], r["amount"], r["usd"]))
        self.stats = {}
        self.cc = {}

    def stat(self, k):
        if k not in self.stats:
            self.stats[k] = drain_stats(self.legs.get(k, []))
        return self.stats[k]

    def code_class(self, r):
        k = (r["chain"], r["address"])
        if k in self.cc:
            return self.cc[k]
        p = self.per.get(k) or {}
        vf = self.verified.get(k) or {}
        tc = self.tron.get(r["address"]) if r["chain"] == "tron" else None
        names = [vf.get("name"), (tc or {}).get("name")]
        if vf.get("name") and "(proxy of " in vf["name"]:
            names.append(vf["name"].split("(proxy of ", 1)[1].rstrip(")"))
        flags = dict(kit=p.get("kit") or (tc or {}).get("kit"), kit_exact=p.get("kit_exact"),
                     kit_public=p.get("kit_public"), redflags=p.get("redflags"),
                     puller=p.get("puller") or bool((tc or {}).get("puller")), verified=vf.get("verified"),
                     proxy=vf.get("proxy"), safe_proxy=p.get("safe_proxy"))
        self.cc[k] = codeclass.classify(r.get("size"), self.sels.get(k, []), names, (tc or {}).get("abi"), flags,
                                        self.sigs)
        return self.cc[k]


def perm_crews(ctx, rows):
    """TRON permission-hijack keys whose drains went to a collector shared by >= 2 hijacking keys (not itself a key or
    a hijacked account): a crew sweeping taken-over accounts. Self-migrations pay their own old recipients instead."""
    keys = {(r["chain"], r["address"]) for r in rows if set(r["labels"]) & {"perm_hijack", "perm_hijack_drain"}}
    by_rec = defaultdict(set)
    victims = set()
    for k in keys:
        for _, v, rc, _, _ in ctx.legs.get(k, []):
            victims.add(v)
            if rc:
                by_rec[(k[0], rc)].add(k[1])
    crew = set()
    for (chain, rc), ctrls in by_rec.items():
        if len(ctrls) >= 2 and rc not in victims and (chain, rc) not in keys:
            crew |= {(chain, c) for c in ctrls}
    return crew


def policy_tier(r, cc, shapes, crew, harm):
    """-> (tier, cap label or None) for one row (labels / victims / drains as rolled up)."""
    lb = set(r["labels"])
    pulled = r["victims"] >= 1 and (r["drains"] > 0 or bool(lb & PULL_EVIDENCE))
    strong = lb & STRONG
    if strong and (strong - STATIC_STRONG or pulled):
        return "T1", None
    if cc == "legit_code":
        return "T3", "legit_code_capped"
    if shapes and "wa_scam" not in lb:          # an independent scam / hack attribution is not a service
        return "T3", "service_shape_capped"
    if cc == "drainer_code" and pulled:
        return "T1", None
    core = lb - WEAK
    if cc not in ("drainer_code", "tiny"):
        core -= SPLIT_SHAPE
    if crew:
        core.add("perm_hijack_multi")
    if harm:
        core.add("eoa_spender_multi")
    active = r["victims"] > 0 or r["drains"] > 0 or bool(lb & PULL_EVIDENCE)
    t = assign_tier(core, r["victims"], active) or "T3"
    if t == "T3" and "cluster_inherited" in core:
        t = "T2"                                  # R-A4 inheritance, granted by rollup.clusters() on post-policy tiers
    if t == "T1":
        t = "T2"                                  # T1 needs own proof (a kit fingerprint or drainer code + a pull)
    return t, ("weak_only_capped" if t == "T3" else None)


def apply(ctx, rows, final=False):
    """Re-tier rows in place (lower only). Sets r['code_class'], r['category'] ('poisoning' or None) and r['rule_tier']
    (the best tier the detector rules gave before this policy: what the labels alone would have meant)."""
    crew = perm_crews(ctx, rows)
    shapes_by_addr = defaultdict(set)              # a service shape on one chain applies to the address's twins
    for r in rows:
        k = (r["chain"], r["address"])
        rt = r.get("rule_tier")
        r["rule_tier"] = r["tier"] if not rt or RANK[r["tier"]] < RANK[rt] else rt
        cc = ctx.code_class(r)
        r["code_class"] = cc
        if r["tier"] in ("T1", "T2") and not set(r["labels"]) & STRONG:
            sh = service_shapes(ctx.stat(k), cc not in ("eoa",))
            if sh:
                shapes_by_addr[(r["address"], r.get("code_hash"))] |= sh
    for r in rows:
        k = (r["chain"], r["address"])
        lb = set(r["labels"])
        cc = r["code_class"]
        poison = (bool(lb & POISON_LABELS) or cc == "poisoner") and not (lb & STRONG - STATIC_STRONG) \
            and cc != "drainer_code"               # kit evidence or drainer code wins over poisoning noise
        r["category"] = "poisoning" if poison else r.get("category")
        if poison:
            r["tier"] = "T3"
            continue
        if r["tier"] == "T3":
            continue
        shapes = shapes_by_addr.get((r["address"], r.get("code_hash")), set())
        harm = "eoa_spender_multi" in lb and ("wa_scam" in lb or harm_ok(ctx.stat(k)))
        t, cap = policy_tier(r, cc, shapes, k in crew, harm)
        if RANK[t] > RANK[r["tier"]]:
            r["tier"] = t
            if cap:
                r["labels"] = sorted(lb | {cap})
    if final:
        poison_deployers(ctx, rows)


def poison_deployers(ctx, rows):
    """A serial deployer (W13) whose flagged contracts are mostly poisoners is a poisoning operator, not a drainer one."""
    idx = {(r["chain"], r["address"]): r for r in rows}
    dep = defaultdict(set)
    for q, col in (("SELECT chain,address,deployer FROM creations", "deployer"),
                   ("SELECT chain,address,deployer FROM contract_deployer", "deployer")):
        for x in ctx.conn.execute(q):
            if x[col] and (x["chain"], x["address"]) in idx:
                dep[(x["chain"], x[col])].add(x["address"])
    for r in rows:
        if "serial_deployer" not in r["labels"]:
            continue
        kids = [idx[(r["chain"], a)] for a in dep.get((r["chain"], r["address"]), ())]
        if kids and sum(1 for c in kids if c.get("category") == "poisoning") * 2 >= len(kids):
            r["category"] = "poisoning"
            r["tier"] = "T3"
