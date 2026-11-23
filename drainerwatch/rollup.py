"""Roll evidence up into the `contracts` table: labels, tier, score, victims, family."""
import hashlib
import json
from collections import defaultdict

from . import bytecode
from .constants import (ALLOWLIST, CHAINS, AMM_FACTORIES, D4_MIN_TXS, D10_MIN_VICTIMS, D10_WINDOW, MALICIOUS_CATEGORIES, MIN_USD,
                        ONESHOT_T1_WORKERS, POOL_SELECTORS)
from .detectors import assign_tier, score_of, window_hit
from .seeds import load_allowlist
from .util import iso, now_ts

ACTIVITY_TYPES = {"seed_activity", "split_pull", "pays_known_operator", "redflag_payable", "multi_victim_pull",
                  "eoa_spender_pull", "approval_fingerprint", "bait_payable", "bait_withdraw", "split_xtx",
                  "foreign_recipient_swap", "owner_collect", "oneshot_spender", "ms_deadline", "batch_approval_drain",
                  "kit_router_swap", "kit_deposit", "gen_back_transfer"}
# labels that come from code alone (no on-chain behaviour): never enough for cluster tier inheritance
STATIC_LABELS = {"redflag_selectors", "family_match", "kit_signature", "owner_gated_puller", "wa_scam", "kit_exact",
                 "cross_chain", "cross_chain_t1", "eip7702_operator"}
# kit K-rules rules whose evidence type is also the label
KIT_EVIDENCE_LABELS = ("owner_collect", "ms_deadline", "batch_approval_drain", "kit_router_swap", "kit_deposit",
                       "gen_back_transfer")
TIER_RANK = {"T1": 1, "T2": 2, "T3": 3}
# an Etherscan-verified contract whose only behavioural evidence is one of these is capped at T3: drainers are virtually
# always unverified, while generic multicall utilities and vault/redemption contracts look exactly like a split pull
VERIFIED_CAPPABLE = {"split_pull", "split_xtx", "multi_victim_pull", "cross_chain", "redflag_selectors",
                     "pays_inferred_operator"}
BEHAVIOUR_CAPPED = {"split_pull", "split_xtx", "multi_victim_pull"}


def allow_sets():
    """chain -> benign addresses: built-in ALLOWLIST + data/allowlist.csv (global and per chain)."""
    return {ch: set(ALLOWLIST) | load_allowlist(ch) for ch in CHAINS}


def purge_allowlisted(conn, allow):
    """Drop stored evidence / drains / payouts of allowlisted subjects and payout wallets, whatever was recorded before
    the address was added to the allowlist."""
    n = 0
    for ch, addrs in allow.items():
        for a in addrs:
            for sql, args in (("DELETE FROM evidence WHERE chain=? AND address=?", (ch, a)),
                              ("DELETE FROM drains WHERE chain=? AND drainer=?", (ch, a)),
                              ("DELETE FROM payouts WHERE chain=? AND (drainer=? OR wallet=?)", (ch, a, a))):
                n += max(0, conn.execute(sql, args).rowcount)
    return n


def load_verified(conn):
    """(chain, address) -> dict(verified, name); a proxy counts as verified only if its implementation is."""
    out = {}
    for r in conn.execute("SELECT * FROM verified_cache"):
        if r["proxy"]:
            ver = None if r["impl_verified"] is None else bool(r["impl_verified"])
            if r["impl_name"]:
                name = f"{r['name'] or '?'} (proxy of {r['impl_name']})"
            else:
                name = f"{r['name'] or '?'} (proxy, implementation " + ("unknown)" if ver is None else "unverified)")
        else:
            ver, name = bool(r["verified"]), r["name"]
        out[(r["chain"], r["address"])] = dict(verified=ver, name=name)
    return out


def is_legit_subject(chain, addr, labels, dep=None, sels=None, allow=None):
    """Never flag: allowlisted addresses, wallet-attribution labelled with a non-malicious category, anything created by
    a known AMM factory (when the creator/factory is resolved), or a contract whose dispatcher has token0()+token1()
    (AMM pair/pool)."""
    if addr in (allow or {}).get(chain, ()):
        return True
    lb = labels.get((chain, addr))
    if lb and lb[1] not in MALICIOUS_CATEGORIES:
        return True
    d = (dep or {}).get((chain, addr))
    if d and (d["deployer"] in AMM_FACTORIES or d["factory"] in AMM_FACTORIES):
        return True
    return POOL_SELECTORS <= (sels or {}).get((chain, addr), set())


def rollup(conn, seeds, labels, now=None):
    now = now or now_ts()
    allow = allow_sets()
    purge_allowlisted(conn, allow)
    verified = load_verified(conn)
    per = defaultdict(lambda: dict(types=defaultdict(list), victims=set(), mvp=[], esp=[], tx_d4=set(), tx_d4w=set(), spoof=False, real_split=False, fam=None,
                                   redflags=False, ts=[], kit=None, puller=False, frs=[], frs_all=[], frs_kit=False,
                                   osp=[], msd_pulled=False, op7702=False, kit_exact=None, xchain=[]))
    for r in conn.execute("SELECT chain,address,type,tx,ts,detail FROM evidence"):
        p = per[(r["chain"], r["address"])]
        d = json.loads(r["detail"] or "{}")
        t = r["type"]
        p["types"][t].append(r["tx"])
        if r["ts"]:
            p["ts"].append(r["ts"])
        if t == "seed_activity":
            p["victims"].add(d.get("victim"))
        elif t == "split_pull":
            if d.get("spoof"):
                p["spoof"] = True
            else:
                p["real_split"] = True
                p["victims"].update(d.get("victims", []))
        elif t == "eoa_spender_pull":
            p["esp"].append((r["ts"], d.get("victim")))
        elif t == "multi_victim_pull":
            p["mvp"] += [(r["ts"], v) for v in d.get("victims", [])]
        elif t == "pays_known_operator":
            (p["tx_d4"] if d.get("strong") else p["tx_d4w"]).add(r["tx"])
        elif t == "bytecode":
            if d.get("redflags"):
                p["redflags"] = True
            if d.get("family"):
                p["fam"] = d["family"]
            if d.get("kit"):
                p["kit"] = d["kit"]
            if d.get("owner_gated_puller"):
                p["puller"] = True
            if d.get("kit_exact"):
                p["kit_exact"] = d["kit_exact"]
        elif t in ("approval_fingerprint", "bait_payable"):
            p["victims"].add(d.get("victim"))
        elif t == "split_xtx":
            p["victims"].update(d.get("victims", []))
        elif t == "foreign_recipient_swap":
            p["frs_all"].append((r["ts"], d.get("victim")))
            if d.get("usd") is not None and d["usd"] >= MIN_USD:
                p["frs"].append((r["ts"], d.get("victim")))
            p["frs_kit"] = p["frs_kit"] or bool(d.get("kit"))
        elif t == "eip7702_sweeper":
            p["victims"].update(d.get("delegators", []))
        elif t == "owner_collect":
            p["victims"].add(d.get("victim"))
            p["op7702"] = p["op7702"] or bool(d.get("operator_7702"))
        elif t == "oneshot_spender":
            p["osp"].append(d)
            p["victims"].add(d.get("victim"))
            p["op7702"] = p["op7702"] or bool(d.get("hub_7702"))
        elif t == "ms_deadline":
            p["victims"].add(d.get("victim"))
            p["msd_pulled"] = p["msd_pulled"] or bool(d.get("pulled"))
        elif t in ("batch_approval_drain", "kit_router_swap"):
            p["victims"].add(d.get("victim"))
        elif t == "cross_chain":
            p["xchain"].append(d)

    dr = {}
    for r in conn.execute("SELECT chain,drainer,COUNT(*) n,COALESCE(SUM(usd),0) usd FROM drains GROUP BY chain,drainer"):
        dr[(r["chain"], r["drainer"])] = (r["n"], r["usd"])
    drain_victims = defaultdict(set)
    for r in conn.execute("SELECT DISTINCT chain,drainer,victim FROM drains"):
        drain_victims[(r["chain"], r["drainer"])].add(r["victim"])
    codes = {(r["chain"], r["address"]): r for r in conn.execute("SELECT chain,address,code_hash,size,skeleton FROM codes")}

    dep = {(r["chain"], r["address"]): r for r in conn.execute("SELECT chain,address,deployer,factory FROM contract_deployer")}
    sels = {(r["chain"], r["address"]): set(json.loads(r["selectors"] or "[]"))
            for r in conn.execute("SELECT chain,address,selectors FROM codes")}
    rows = []
    for (chain, addr), p in per.items():
        if is_legit_subject(chain, addr, labels, dep, sels, allow):
            continue
        lb = set()
        if "seed_activity" in p["types"] and seeds.has(chain, addr):
            lb.add("seed")
        if p["real_split"]:
            lb.add("split_pull")
        elif p["spoof"]:
            lb.add("spoof_split")
        if p["mvp"] and window_hit(p["mvp"]):
            lb.add("multi_victim_pull")
        if p["esp"]:
            lb.add("eoa_spender_pull")
            if window_hit(p["esp"]):
                lb.add("eoa_spender_multi")       # >= 3 distinct victims within 24 h: T2
        if len(p["tx_d4"]) >= D4_MIN_TXS:
            lb.add("pays_known_operator")
        elif len(p["tx_d4"]) + len(p["tx_d4w"]) >= D4_MIN_TXS:
            lb.add("pays_inferred_operator")       # inferred (non-seed / non-T1) operator wallets: T3 at most
        if p["redflags"]:
            lb.add("redflag_selectors")
        if p["fam"]:
            lb.add("family_match")
        if "eip7702_sweeper" in p["types"]:
            lb.add("eip7702_sweeper")
        if "redflag_payable" in p["types"]:
            lb.add("redflag_payable")
        for t in ("approval_fingerprint", "bait_payable", "bait_withdraw", "split_xtx"):
            if t in p["types"]:
                lb.add(t)
        if p["kit"]:
            lb.add("kit_signature")
        for t in KIT_EVIDENCE_LABELS:
            if t in p["types"]:
                lb.add(t)
        if p["msd_pulled"]:
            lb.add("ms_deadline_pull")
        if p["kit_exact"]:
            lb.add("kit_exact")
        if p["osp"]:                               # K5 / K12 hub aggregation
            workers = {d.get("worker") for d in p["osp"]}
            ret = {d.get("worker") for d in p["osp"] if d.get("return_tx")}
            if ret:
                lb.add("oneshot_hub")
                if len(workers) >= ONESHOT_T1_WORKERS:
                    lb.add("oneshot_multi")
            else:
                lb.add("prefund_hub")
                if len(workers) >= ONESHOT_T1_WORKERS:
                    lb.add("prefund_multi")
        if p["op7702"] and lb & {"owner_collect", "oneshot_hub", "prefund_hub"}:
            lb.add("eip7702_operator")            # K13: score boost only
        if p["xchain"]:
            lb.add("cross_chain")
            if any(d.get("linked_tier") == "T1" for d in p["xchain"]):
                lb.add("cross_chain_t1")
        if p["puller"]:
            lb.add("owner_gated_puller")
        if p["frs_all"]:
            lb.add("foreign_recipient_swap")
            if window_hit(p["frs"], D10_WINDOW, D10_MIN_VICTIMS):
                lb.add("foreign_swap_multi")
            if p["frs_kit"]:
                lb.add("foreign_swap_kit")
        victims = {v for v in p["victims"] | drain_victims.get((chain, addr), set()) | {v for _, v in p["mvp"]}
                   | {v for _, v in p["esp"]} | {v for _, v in p["frs_all"]} if v}
        n_dr, usd = dr.get((chain, addr), (0, 0.0))
        active = bool(victims) or n_dr > 0 or bool(ACTIVITY_TYPES & set(p["types"]))
        tier = assign_tier(lb, len(victims), active)
        if not tier:
            continue
        wl = labels.get((chain, addr))
        if wl and wl[1] in ("scam", "hack"):
            lb.add("wa_scam")
        vf = verified.get((chain, addr))
        if vf and vf["verified"] and tier in ("T1", "T2") and lb & BEHAVIOUR_CAPPED and lb <= VERIFIED_CAPPABLE:
            tier = "T3"
            lb.add("verified_capped")
        c = codes.get((chain, addr))
        ts = p["ts"] or [now]
        src = seeds.get(chain, addr)[1] if "seed" in lb else "detector"
        rows.append(dict(chain=chain, address=addr, tier=tier, score=score_of(lb, len(victims), usd, active),
                         source=src, family=p["fam"] or p["kit"], labels=sorted(lb), first=min(ts), last=max(ts),
                         victims=len(victims), drains=n_dr, usd=round(usd, 2),
                         code_hash=c["code_hash"] if c else None, size=c["size"] if c else None,
                         is_contract=(1 if c["size"] else 0) if c else None, skeleton=c["skeleton"] if c else None,
                         verified=None if not vf or vf["verified"] is None else int(vf["verified"]),
                         contract_name=vf["name"] if vf else None))

    cross_chain_rows(rows)
    # families: evidence family, its anchor skeleton (the seed itself), and shared skeletons between tracked contracts
    fams = {r["family"] for r in rows if r["family"]}
    by_skel = defaultdict(list)
    for r in rows:
        if r["skeleton"] and (r["size"] or 0) >= 100:
            by_skel[r["skeleton"]].append(r)
    for sk, group in by_skel.items():
        fid = bytecode.family_id(sk)
        if fid in fams or len(group) >= 2:
            for r in group:
                r["family"] = r["family"] or fid
    clusters(conn, rows, labels, allow)
    conn.execute("DELETE FROM contracts")
    conn.executemany(
        "INSERT INTO contracts(chain,address,tier,score,source,family,labels,first_seen,last_seen,victims,drains,usd,"
        "code_hash,code_size,is_contract,verified,cluster,contract_name) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        [(r["chain"], r["address"], r["tier"], r["score"], r["source"], r["family"], json.dumps(r["labels"]),
          iso(r["first"]), iso(r["last"]), r["victims"], r["drains"], r["usd"], r["code_hash"], r["size"],
          r["is_contract"], r["verified"], r.get("cluster"), r["contract_name"]) for r in rows])
    conn.commit()
    return rows


def cross_chain_rows(rows):
    """K14 / S6: the same address flagged on >= 2 chains with the same opcode skeleton (same deployer + nonce, same
    code) is one operator's reuse: label `cross_chain` on every twin, `cross_chain_t1` (T2) on twins of a T1. Uses own
    tiers only. Mutates rows in place."""
    by_addr = defaultdict(list)
    for r in rows:
        if r["skeleton"] and (r["size"] or 0) >= 100 and "verified_capped" not in r["labels"]:
            by_addr[(r["address"], r["skeleton"])].append(r)
    for group in by_addr.values():
        if len({r["chain"] for r in group}) < 2:
            continue
        own = {r["chain"]: r["tier"] for r in group}
        for r in group:
            lb = set(r["labels"]) | {"cross_chain"}
            if any(t == "T1" for c, t in own.items() if c != r["chain"]):
                lb.add("cross_chain_t1")
            r["labels"] = sorted(lb)
            new = assign_tier(lb, r["victims"], True)
            if new and TIER_RANK[new] < TIER_RANK[r["tier"]]:
                r["tier"] = new


def clusters(conn, rows, labels=None, allow=None):
    """R-A4 shared collectors. Flagged subjects (contracts or EOA drainers) that share a payout wallet (split payout,
    D8 collector, MS customer) form one operator cluster: union-find over (chain, payout wallet) with >= 2 flagged
    subjects. cluster id = "op_" + sha256(chain:min shared wallet)[:10] (stable while that wallet stays shared).
    Tier inheritance (label cluster_inherited): a member is raised to the cluster's best OWN tier only if
      * both it and the better-tier member have their own behavioural evidence (labels outside STATIC_LABELS), and
      * the link is not a single weak one: >= 2 shared wallets with better-tier members, or >= 2 payout txs to them,
        and at least one shared wallet is not a customer-only link (multi-tenant MS bait contracts share customers).
    Inheritance is computed from own tiers only (no chaining through inherited tiers). Mutates rows in place."""
    flagged = {(r["chain"], r["address"]): r for r in rows}
    by_wallet = defaultdict(list)
    for p in conn.execute("SELECT chain,drainer,wallet,role,txs FROM payouts"):
        k = (p["chain"], p["drainer"])
        if k in flagged and p["wallet"] != p["drainer"] and not is_legit_subject(p["chain"], p["wallet"], labels or {},
                                                                                  allow=allow):
            by_wallet[(p["chain"], p["wallet"])].append(dict(drainer=p["drainer"], role=p["role"], txs=p["txs"] or 0))
    shared = {w: m for w, m in by_wallet.items() if len({x["drainer"] for x in m}) >= 2}
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for (chain, _), members in shared.items():
        ks = [(chain, x["drainer"]) for x in members]
        for k in ks[1:]:
            parent[find(ks[0])] = find(k)
    groups = defaultdict(list)
    for k in list(parent):
        groups[find(k)].append(k)
    own = {k: r["tier"] for k, r in flagged.items()}
    for root, members in groups.items():
        chain = members[0][0]
        wallets = sorted(w for (c, w), m in shared.items() if c == chain and (c, m[0]["drainer"]) in parent
                         and find((c, m[0]["drainer"])) == root)
        cid = "op_" + hashlib.sha256(f"{chain}:{wallets[0]}".encode()).hexdigest()[:10]
        best = min(TIER_RANK[own[k]] for k in members)
        for k in members:
            r = flagged[k]
            r["cluster"] = cid
            if TIER_RANK[own[k]] <= best or "verified_capped" in r["labels"]:
                continue
            if not (set(r["labels"]) - STATIC_LABELS - {"cluster_inherited"}):
                continue                                   # static-only member: no independent evidence
            better = {m for m in members if TIER_RANK[own[m]] == best
                      and set(flagged[m]["labels"]) - STATIC_LABELS - {"cluster_inherited"}}
            links = [(w, x) for (c, w), ms in shared.items() if c == chain
                     for x in ms if x["drainer"] == k[1] and any((c, y["drainer"]) in better for y in ms)]
            if not links:
                continue
            n_wallets = len({w for w, _ in links})
            n_txs = sum(x["txs"] for _, x in links)
            if n_wallets < 2 and n_txs < 2:
                continue                                   # single weak link
            if all(x["role"] == "customer" for _, x in links):
                continue
            target = max(best, 2)                          # inheritance never grants T1: T1 needs own evidence
            if TIER_RANK[own[k]] <= target:
                continue
            r["tier"] = {2: "T2", 3: "T3"}[target]
            r["labels"] = sorted(set(r["labels"]) | {"cluster_inherited"})
