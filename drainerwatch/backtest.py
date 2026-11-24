"""Blind backtest on real incidents (tests/backtest/incidents.csv).

For every component of incidents (seed + its drainer contract, same grouping as the dev/holdout split) the full pipeline
runs into a fresh in-memory db over the incident blocks +/- `window`, using the receipts source (eth_getBlockReceipts +
full blocks: no getLogs, no tx lookups). With --blind:
  * seeds are disabled for detection (no D1, no seed-based D4 / strong wallets);
  * the bytecode family library is built ONLY from dev-split targets: for dev, the dev targets of OTHER components
    (leave-one-component-out); for holdout, all dev targets. A seed therefore never matches itself.
Scoring: an incident is detected when its seed address or its tx.to drainer contract is flagged (T1/T2; any tier also
reported). Everything else flagged at T1/T2 in the same blocks is a false-positive candidate and is classified with
ScamSniffer membership (likely unlabeled true positive), wallet-attribution labels and Etherscan ContractName."""
import json
import logging
import time
from collections import Counter, defaultdict

from . import bytecode, enrich, incidents, rollup, scan, seeds as seedmod
from .db import connect
from .prices import Prices
from .rpc import Rpc
from .seeds import SeedSet
from .util import iso

log = logging.getLogger("drainerwatch.backtest")

DETECTOR_LABELS = ["seed", "split_pull", "multi_victim_pull", "eoa_spender_pull", "eoa_spender_multi", "pays_known_operator",
                   "pays_inferred_operator", "family_match", "redflag_selectors", "redflag_payable", "eip7702_sweeper",
                   "spoof_split", "approval_fingerprint", "bait_payable", "bait_withdraw", "kit_signature",
                   "owner_gated_puller", "split_xtx", "foreign_recipient_swap", "foreign_swap_multi", "foreign_swap_kit",
                   "cluster_inherited", "owner_collect", "ms_deadline", "ms_deadline_pull", "oneshot_hub", "oneshot_multi",
                   "prefund_hub", "prefund_multi", "batch_approval_drain", "kit_router_swap", "kit_exact", "kit_deposit",
                   "gen_back_transfer", "eip7702_operator", "cross_chain", "cross_chain_t1", "kit_public",
                   "kit_confirmed", "ms_cashback", "ms_cashback_shape", "dust_approve", "dust_approve_kit", "emergency_gas",
                   "emergency_gas_kit", "emergency_gas_self", "kit_vanity", "unpriced_capped",
                   # web-research rules W1-W13
                   "vanity_drainer", "deploy_drain", "deploy_drain_weak", "ghost_forward", "ghost_forward_multi", "bait_forward",
                   "bait_forward_multi", "kept_share", "token_spender_pull", "token_spender_multi", "owner_takeover",
                   "owner_takeover_multi", "safe_spender", "safe_spender_pull", "seaport_zero", "seaport_zero_multi",
                   "nft_operator_pull", "batch7702_approve", "eip7702_batch", "eip7702_chain0", "poison_zero",
                   "share_grid", "operator_wallet", "operator_wallet_multi", "serial_deployer", "serial_deployer_multi",
                   # GitHub / paper research rules G1-G13
                   "fake_call", "fake_call_multi", "fake_call_contract", "fake_call_contract_multi", "many_funders",
                   "phish_deploy", "phish_multicall", "router_sweep", "router_sweep_multi", "nft_bulk", "nft_bulk_multi",
                   "seaport_fee_drain", "seaport_fee_multi", "poison_tiny", "poison_counterfeit", "poison_batch",
                   "lookalike_contract", "counterfactual_forward", "counterfactual_multi", "codehash_cluster",
                   "forwarder_7702", "forwarder_7702_multi", "batch7702_decoy", "batch7702_decoy_multi",
                   "full_balance_pull", "increase_allowance_eoa", "increase_allowance_pull", "zero_nonce_spender",
                   "zero_nonce_multi", "zero_nonce_pull", "tron_sweeper_kit", "cex_sweep_capped",
                   "tron_eoa_pull", "tron_eoa_pull_multi", "tron_contract_pull", "tron_max_approval"]


def components(rows):
    uf = incidents.UF()
    for r in rows:
        uf.find(r["seed_address"])
        if r["drainer"]:
            uf.union(r["seed_address"], r["drainer"])
    comp = defaultdict(list)
    for r in rows:
        comp[uf.find(r["seed_address"])].append(r)
    return [sorted(v, key=lambda r: r["block"]) for _, v in sorted(comp.items())]


def targets_of(r):
    return {r["seed_address"]} | ({r["drainer"]} if r["drainer"] else set())


def block_ranges(blocks, window):
    s = sorted({b + d for b in blocks for d in range(-window, window + 1)})
    out = []
    for b in s:
        if out and b == out[-1][1] + 1:
            out[-1][1] = b
        else:
            out.append([b, b])
    return [tuple(x) for x in out]


def family_library(rpc, addrs, code_cache):
    need = [a for a in addrs if a not in code_cache]
    if need:
        code_cache.update({a: c for a, c in rpc.get_code_many(need).items() if c is not None})
    lib = []
    for a in sorted(addrs):
        c = code_cache.get(a)
        if not c or c == "0x" or bytecode.is_delegated_eoa(c):
            continue
        info = bytecode.analyze(c)
        if info["skeleton"]:
            lib.append(dict(address=a, skeleton=info["skeleton"], selectors=set(info["selectors"]), size=info["size"]))
    return lib


class Classifier:
    """FP classification: ScamSniffer membership, wallet-attribution label, Etherscan ContractName (cached, capped)."""

    def __init__(self, conn, labels, ss, es):
        self.conn, self.labels, self.ss, self.es = conn, labels, ss, es
        conn.execute("CREATE TABLE IF NOT EXISTS bt_names(address TEXT PRIMARY KEY, name TEXT)")

    def name(self, addr):
        r = self.conn.execute("SELECT name FROM bt_names WHERE address=?", (addr,)).fetchone()
        if r:
            return r["name"]
        res = self.es.call("eth", dict(module="contract", action="getsourcecode", address=addr)) if self.es else None
        if res is None:
            return None
        nm = (res[0].get("ContractName") if res else "") or ""
        self.conn.execute("INSERT OR REPLACE INTO bt_names VALUES(?,?)", (addr, nm))
        self.conn.commit()
        return nm

    def classify(self, addr):
        lb = self.labels.get(("eth", addr))
        nm = self.name(addr)
        if addr in self.ss:
            kind = "scamsniffer seed (likely unlabeled TP)"
        elif lb and lb[1] in ("scam", "hack"):
            kind = f"wa {lb[1]} label (likely unlabeled TP)"
        elif lb:
            kind = f"wa label {lb[1]}: legit"
        elif nm:
            kind = "verified contract"
        else:
            kind = "unverified / unknown"
        return dict(kind=kind, wa=f"{lb[0]} / {lb[2]} ({lb[1]})" if lb else "", name=nm or "")


def run(incidents_path, split, blind=True, window=1, budget_sec=7200, cache_path=None, max_components=None):
    t0 = time.monotonic()
    all_rows = [r for r in incidents.load(incidents_path) if (r.get("chain") or "eth") == "eth"]   # ETH pipeline only
    rows = [r for r in all_rows if r["split"] == split]
    cache = connect(cache_path)
    enrich.refresh_labels(cache, ["eth"])
    labels = enrich.load_labels(cache)
    prices = Prices(cache)
    prices.refresh()
    ss = set(seedmod.fetch_scamsniffer())
    es = enrich.Etherscan(calls_cap=2000)
    rpc = Rpc("eth")
    code_cache = {}
    all_targets = set().union(*(targets_of(r) for r in all_rows)) if all_rows else set()
    incident_addrs = all_targets | {r["tx_to"] for r in all_rows if r["tx_to"]} | {r["tx_from"] for r in all_rows}
    dev_comps = components([r for r in all_rows if r["split"] == "dev"])
    comps = components(rows)[:max_components] if max_components else components(rows)
    det_seeds = SeedSet() if blind else SeedSet((a, None, "ScamSniffer blacklist", "scamsniffer") for a in ss)
    tok_rows = [tuple(r) for r in cache.execute("SELECT chain,address,symbol,decimals FROM tokens")]
    results, fps, stats = [], [], Counter()
    for ci, comp in enumerate(comps):
        if time.monotonic() - t0 > budget_sec:
            log.warning("budget exhausted after %d/%d components", ci, len(comps))
            break
        comp_targets = set().union(*(targets_of(r) for r in comp))
        lib_addrs = set()
        for dc in dev_comps:
            t = set().union(*(targets_of(r) for r in dc))
            if not (t & comp_targets):
                lib_addrs |= t
        lib = family_library(rpc, lib_addrs, code_cache) if blind else None
        conn = connect(":memory:")
        conn.executemany("INSERT OR REPLACE INTO tokens VALUES(?,?,?,?)", tok_rows)
        conn.executemany("INSERT OR REPLACE INTO labels(chain,address,entity,label,category) VALUES(?,?,?,?,?)",
                         [(c, a, v[0], v[2], v[1]) for (c, a), v in labels.items() if c == "eth"])
        ranges = block_ranges([r["block"] for r in comp], window)
        for a, b in ranges:
            st = scan.scan_chain(conn, "eth", det_seeds, labels, prices, rpc=rpc, start=a, end=b, persist_cursor=False,
                                 source="receipts", code_cache=code_cache, family_index=lib,
                                 deadline=time.monotonic() + 900)
            stats["blocks"] += st["blocks"]
            for k in ("d2_candidates", "d2_confirmed", "d3_candidates", "d3_confirmed", "d8_candidates", "d8_confirmed", "d8_truncated", "d9_confirmed", "d7_bait", "d10_confirmed", "xsplit_groups", "xsplit_confirmed",
                      "k4_ms_deadline", "k5_oneshot", "k6_kit_deposit", "k9_owner_collect", "k7k8_batch_approval_drain",
                      "k7k8_kit_router_swap", "d7_ms_new", "d7_ms_generated", "n4_dust_approve", "n5_emergency_gas",
                      "n7_kit_router_xtx", "w1_deploy_drain", "w1_factory_drain", "w1_unknown", "w1_ghost_forward",
                      "w2_vanity_approval", "w3_bait_forward", "w3_unknown", "w4_token_spender", "w5_owner_takeover",
                      "w6_safe_approval", "w6_safe_pull", "w7_seaport_zero", "w7_nft_operator", "w8_batch7702",
                      "w8_auth_batch", "w10_poison_zero", "w_errors",
                      "tx_lookups", "code_lookups", "nonce_lookups"):
                stats[k] += st.get(k, 0)
        rows0 = rollup.rollup(conn, det_seeds, labels)
        enrich.lookup_verified(conn, es, rows0, cap=60)       # verified-source cap (T3) for split-only evidence
        enrich.victim_funding(conn, es, rows0, labels, cap=10)  # CEX deposit-sweep guard
        flagged = {r["address"]: r for r in rollup.rollup(conn, det_seeds, labels)}
        payouts = defaultdict(list)
        for p in conn.execute("SELECT drainer,wallet,role,share,txs FROM payouts"):
            payouts[p["drainer"]].append(dict(p))
        for r in comp:
            hit = [flagged[t] for t in targets_of(r) if t in flagged]
            best = min(hit, key=lambda x: x["tier"]) if hit else None
            pw = {p["wallet"] for t in targets_of(r) for p in payouts.get(t, [])}
            # payout attribution: seed is a payout wallet -> was it recovered as payout of any flagged contract?
            seed_as_payout = any(p["wallet"] == r["seed_address"] for ps in payouts.values() for p in ps)
            results.append(dict(r, tier=best["tier"] if best else "", labels=best["labels"] if best else [],
                                flagged_addr=best["address"] if best else "", payouts=sorted(pw),
                                seed_as_payout=seed_as_payout))
        for addr, f in flagged.items():
            if f["tier"] in ("T1", "T2") and addr not in comp_targets:
                fps.append(dict(f, component=comp[0]["seed_address"], known_incident_addr=addr in incident_addrs,
                                ev=[dict(type=e["type"], tx=e["tx"]) for e in conn.execute(
                                    "SELECT type,tx FROM evidence WHERE address=? ORDER BY id LIMIT 3", (addr,))]))
        # share token metadata across components
        tok_rows = [tuple(x) for x in conn.execute("SELECT chain,address,symbol,decimals FROM tokens")]
        log.info("component %d/%d %s: %d incidents, ranges %d, detected T1/T2 %d", ci + 1, len(comps),
                 comp[0]["seed_address"], len(comp), len(ranges),
                 sum(1 for x in results[-len(comp):] if x["tier"] in ("T1", "T2")))
    cache.executemany("INSERT OR REPLACE INTO tokens VALUES(?,?,?,?)", tok_rows)
    cache.commit()
    cl = Classifier(cache, labels, ss, es)
    for f in fps:
        f.update(cl.classify(f["address"]))
    stats["rpc_calls"], stats["rpc_errors"] = rpc.calls, rpc.errors
    stats["etherscan_calls"] = es.calls
    stats["elapsed_sec"] = int(time.monotonic() - t0)
    return dict(split=split, blind=blind, window=window, results=results, fps=fps, stats=dict(stats))


# ---------- metrics / report ----------
def metrics(res):
    R = res["results"]
    n = len(R)
    t12 = [r for r in R if r["tier"] in ("T1", "T2")]
    anyt = [r for r in R if r["tier"]]
    per_det = Counter(lb for r in anyt for lb in r["labels"])
    per_det_t12 = Counter(lb for r in t12 for lb in r["labels"])
    by_pattern = defaultdict(lambda: [0, 0])
    by_role = defaultdict(lambda: [0, 0])
    for r in R:
        by_pattern[r["pattern"].split(":")[0]][0] += 1
        by_role[r["role_of_seed"]][0] += 1
        if r["tier"] in ("T1", "T2"):
            by_pattern[r["pattern"].split(":")[0]][1] += 1
            by_role[r["role_of_seed"]][1] += 1
    tp_addrs = {r["flagged_addr"] for r in t12}
    fp = res["fps"]
    fp_addrs = {f["address"] for f in fp}
    fp_likely_tp = {f["address"] for f in fp if "likely unlabeled TP" in f.get("kind", "") or f["known_incident_addr"]}
    prec = len(tp_addrs) / (len(tp_addrs) + len(fp_addrs)) if (tp_addrs or fp_addrs) else None
    prec_adj = len(tp_addrs | fp_likely_tp) / (len(tp_addrs) + len(fp_addrs)) if (tp_addrs or fp_addrs) else None
    seeds = {r["seed_address"] for r in R}
    seeds_hit = {r["seed_address"] for r in t12}
    payout_inc = [r for r in R if r["role_of_seed"] == "payout"]
    return dict(n=n, seeds=len(seeds), recall_t12=len(t12) / n if n else 0, recall_any=len(anyt) / n if n else 0,
                det_t12=len(t12), det_any=len(anyt), seeds_hit=len(seeds_hit), per_det=dict(per_det),
                per_det_t12=dict(per_det_t12), by_pattern={k: tuple(v) for k, v in by_pattern.items()},
                by_role={k: tuple(v) for k, v in by_role.items()}, tp_addrs=len(tp_addrs), fp_addrs=len(fp_addrs),
                fp_likely_tp=len(fp_likely_tp), precision=prec, precision_adj=prec_adj,
                payout_incidents=len(payout_inc), payout_recovered=sum(1 for r in payout_inc if r["seed_as_payout"]),
                with_payouts=sum(1 for r in t12 if r["payouts"]))


def pct(x):
    return "n/a" if x is None else f"{100 * x:.1f}%"


def report_md(res, baseline=None, title_extra=""):
    m = metrics(res)
    L = [f"# Backtest report: {res['split']}{title_extra}", "",
         f"Generated {iso(int(time.time()))}. Mode: {'BLIND (seeds disabled for detection; family library = dev targets only, own component excluded)' if res['blind'] else 'seeded'}; "
         f"source: eth_getBlockReceipts + full blocks; window +/-{res['window']} blocks around each incident.", "",
         "## Summary", "", "| metric | value |" + (" baseline |" if baseline else ""), "|---|---|" + ("---|" if baseline else "")]
    mb = metrics(baseline) if baseline else None

    def row(name, key, f=lambda v: str(v)):
        L.append(f"| {name} | {f(m[key])} |" + (f" {f(mb[key])} |" if mb else ""))
    row("incidents", "n")
    row("distinct seeds", "seeds")
    row("recall T1/T2 (incidents)", "recall_t12", pct)
    row("recall any tier (incidents)", "recall_any", pct)
    row("seeds with >=1 T1/T2 detection", "seeds_hit")
    row("TP flagged addresses (T1/T2)", "tp_addrs")
    row("other T1/T2 flagged addresses (FP candidates)", "fp_addrs")
    row("  of which ScamSniffer/wa-scam/incident addr (likely TP)", "fp_likely_tp")
    row("precision strict (TP / all T1-T2 flagged)", "precision", pct)
    row("precision adjusted (likely-TP FPs counted as TP)", "precision_adj", pct)
    row("payout-role incidents", "payout_incidents")
    row("  seed recovered as payout wallet", "payout_recovered")
    row("detected incidents with payout wallets", "with_payouts")
    L += ["", "## Recall per detector (incidents whose flagged target carries the label)", "",
          "| detector | any tier | T1/T2 |" + (" baseline any / T1-T2 |" if mb else ""), "|---|---|---|" + ("---|" if mb else "")]
    for d in DETECTOR_LABELS:
        if m["per_det"].get(d) or (mb and mb["per_det"].get(d)):
            L.append(f"| {d} | {m['per_det'].get(d, 0)} | {m['per_det_t12'].get(d, 0)} |" +
                     (f" {mb['per_det'].get(d, 0)} / {mb['per_det_t12'].get(d, 0)} |" if mb else ""))
    L += ["", "## Recall by drain pattern / seed role (detected T1-T2 / total)", "", "| group | value | detected / total |",
          "|---|---|---|"]
    for k, v in sorted(m["by_pattern"].items()):
        L.append(f"| pattern | {k} | {v[1]} / {v[0]} |")
    for k, v in sorted(m["by_role"].items()):
        L.append(f"| seed role | {k} | {v[1]} / {v[0]} |")
    L += ["", "## Incidents", "", "| block | ts | tx | seed | role | pattern | tx.to | flagged | tier | labels | payouts |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in sorted(res["results"], key=lambda r: (r["seed_address"], r["block"])):
        L.append(f"| {r['block']} | {r['ts']} | {r['tx']} | {r['seed_address']} | {r['role_of_seed']} | {r['pattern']} | "
                 f"{r['tx_to']} | {r['flagged_addr']} | {r['tier'] or '-'} | {', '.join(r['labels'])} | "
                 f"{' '.join(r['payouts'])} |")
    L += ["", "## False-positive candidates (T1/T2, not an incident target of the component)", ""]
    if not res["fps"]:
        L.append("None.")
    else:
        L += ["| address | tier | labels | class | wa label | contract name | evidence |", "|---|---|---|---|---|---|---|"]
        for f in sorted(res["fps"], key=lambda f: (f["kind"], f["address"])):
            ev = "; ".join(f"{e['type']} {e['tx']}" for e in f["ev"])
            L.append(f"| {f['address']} | {f['tier']} | {', '.join(f['labels'])} | {f['kind']}"
                     f"{' (incident address)' if f['known_incident_addr'] else ''} | {f['wa']} | {f['name']} | {ev} |")
    L += ["", "## Run stats", "", "```", json.dumps(res["stats"], indent=1), "```", ""]
    return "\n".join(L)
