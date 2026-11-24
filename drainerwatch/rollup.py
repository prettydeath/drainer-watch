"""Roll evidence up into the `contracts` table: labels, tier, score, victims, family."""
import hashlib
import json
from collections import defaultdict

from . import bytecode, wrules
from .constants import (ALLOWLIST, CHAINS, AMM_FACTORIES, D4_MIN_TXS, D10_MIN_VICTIMS, D10_WINDOW, KIT_PUBLIC_CONTRACTS,
                        KIT_VANITY_RE, MALICIOUS_CATEGORIES, MIN_USD, ONESHOT_T1_WORKERS, POOL_SELECTORS, TRON_ALLOWLIST, TRON_FEE_MIN_HITS,
                        OPERATOR_WALLET_T2, SERIAL_DEPLOYER_T2, TRON_PERM_T2, TRON_PREFUND_T2, VANITY_MIN_APPROVERS)
from .detectors import assign_tier, score_of, window_hit
from .seeds import load_allowlist
from .util import iso, now_ts

ACTIVITY_TYPES = {"seed_activity", "split_pull", "pays_known_operator", "redflag_payable", "multi_victim_pull",
                  "eoa_spender_pull", "approval_fingerprint", "bait_payable", "bait_withdraw", "split_xtx",
                  "foreign_recipient_swap", "owner_collect", "oneshot_spender", "ms_deadline", "batch_approval_drain",
                  "kit_router_swap", "kit_deposit", "gen_back_transfer", "dust_approve", "emergency_gas",
                  "kit_pull", "tron_approval", "prefund_approve", "perm_hijack_drain", "fixed_fee",
                  # web-research rules W1-W10
                  "deploy_drain", "ghost_forward", "bait_forward", "token_spender_pull", "owner_takeover", "safe_pull",
                  "seaport_zero", "nft_operator_pull", "batch7702_approve", "vanity_approval", "safe_approval"}
# labels that come from code alone (no on-chain behaviour): never enough for cluster tier inheritance
STATIC_LABELS = {"redflag_selectors", "family_match", "kit_signature", "owner_gated_puller", "wa_scam", "kit_exact",
                 "cross_chain", "cross_chain_t1", "eip7702_operator", "kit_public", "kit_vanity", "share_grid", "kept_share",
                 "oneshot_spender"}
# kit K-rules rules whose evidence type is also the label
KIT_EVIDENCE_LABELS = ("owner_collect", "ms_deadline", "batch_approval_drain", "kit_router_swap", "kit_deposit",
                       "gen_back_transfer")
TIER_RANK = {"T1": 1, "T2": 2, "T3": 3}
# W2: behaviour that turns a vanity address into `vanity_drainer` (besides approvals from 3+ EOAs)
VANITY_BEHAVIOUR = {"bait_payable", "redflag_payable", "bait_forward", "deploy_drain", "ghost_forward", "token_spender_pull",
                    "split_pull", "split_xtx", "multi_victim_pull", "owner_collect", "eoa_spender_pull", "safe_spender_pull"}
# an Etherscan-verified contract whose only behavioural evidence is one of these is capped at T3: drainers are virtually
# always unverified, while generic multicall utilities and vault/redemption contracts look exactly like a split pull
VERIFIED_CAPPABLE = {"split_pull", "split_xtx", "multi_victim_pull", "cross_chain", "redflag_selectors",
                     "pays_inferred_operator", "redflag_payable", "bait_forward", "bait_forward_multi", "token_spender_pull",
                     "token_spender_multi", "share_grid", "kept_share", "deploy_drain", "deploy_drain_weak", "ghost_forward",
                     "ghost_forward_multi"}
BEHAVIOUR_CAPPED = {"split_pull", "split_xtx", "multi_victim_pull", "bait_forward", "bait_forward_multi", "token_spender_pull",
                    "token_spender_multi", "deploy_drain", "ghost_forward", "ghost_forward_multi"}
# a split (D2 / R-A1) of ONE victim with no priced amount (unpriced token, usd 0) and no other behavioural or kit
# evidence is capped at T3: fee-on-transfer / tax-router tokens split every transfer 85/10/5 exactly like a drainer.
# Matters most on chains without Etherscan source verification on our plan (BSC), where the verified cap cannot apply.
UNPRICED_CAPPABLE = {"split_pull", "split_xtx"}
# chains without Etherscan source verification on our plan (BSC, Base): a one-victim split keeps T2 only with one of these
UNVERIFIED_SPLIT_KEEP = {"kit_signature", "owner_gated_puller", "family_match", "seed", "approval_fingerprint",
                         "bait_payable", "kit_exact", "kit_public", "pays_known_operator", "ms_deadline", "vanity_drainer"}
# own evidence that was capped: never re-raised by cross-chain twins (K14) or cluster inheritance
CAPPED_LABELS = {"unpriced_capped", "verified_capped", "tron_split_capped", "unverified_split_capped"}
UNPRICED_NEUTRAL = {"redflag_selectors", "cross_chain", "spoof_split", "share_grid"}


def allow_sets():
    """chain -> benign addresses: built-in ALLOWLIST + data/allowlist.csv (global and per chain)."""
    return {ch: (set(TRON_ALLOWLIST) if CHAINS[ch].get("kind") == "tron" else set(ALLOWLIST)) | load_allowlist(ch)
            for ch in CHAINS}


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
                                   osp=[], msd_pulled=False, op7702=False, kit_exact=None, xchain=[], kit_public=None,
                                   bait_public=False, cashback=False, cashback_shape=False, dust=[], egas=[],
                                   tron_kinds=set(), prefund=[], claimer=False, hijack=set(), fees=[], poison=False,
                                   # web-research rules W1-W11
                                   vapp=set(), ghosts=set(), bfwd=set(), kept=False, tsp=set(), takeovers=set(),
                                   safe_app=set(), safe_pull=set(), sz=set(), a7702=False, a7702_c0=False, grid=False,
                                   dd_strong=False))
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
            if d.get("kit_public"):
                p["kit_public"] = d["kit_public"]
        elif t in ("approval_fingerprint", "bait_payable"):
            p["victims"].add(d.get("victim"))
            if t == "bait_payable":
                p["bait_public"] = p["bait_public"] or bool(d.get("public"))
                if d.get("cashback") and d.get("kit") == "ms_new":
                    if d.get("kit_code") == "ms_new" or d.get("public"):
                        p["cashback"] = True          # N1 with K1: MS_NEW dispatcher + is_cashback = 1
                    else:
                        p["cashback_shape"] = True
        elif t == "redflag_payable":
            p["cashback_shape"] = p["cashback_shape"] or bool(d.get("cashback"))
        elif t == "dust_approve":
            p["dust"].append(d)
            p["victims"].add(d.get("victim"))
        elif t == "emergency_gas":
            p["egas"].append(d)
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
        # TRON rules T-1..T-8
        elif t == "kit_pull":
            p["victims"].add(d.get("victim"))
        elif t == "tron_approval":
            p["victims"].add(d.get("victim"))
            p["tron_kinds"].add(d.get("kind"))
        elif t == "prefund_approve":
            p["prefund"].append((d.get("victim"), d.get("amount_trx")))
            p["victims"].add(d.get("victim"))
        elif t == "perm_hijack":
            p["hijack"].add(d.get("victim"))
            p["victims"].add(d.get("victim"))
        elif t == "perm_hijack_drain":
            p["victims"].add(d.get("victim"))
        elif t == "fixed_fee":
            p["fees"].append((d.get("amount_trx"), d.get("victim"), d.get("pull_tx")))
            p["victims"].add(d.get("victim"))
        elif t in ("zero_transfer_spoof", "poison_zero"):
            p["poison"] = True
        # web-research rules W1-W11
        elif t == "vanity_approval":
            p["vapp"].add(d.get("victim"))
        elif t == "deploy_drain":
            p["victims"].update(d.get("victims", []))
            p["dd_strong"] = p["dd_strong"] or d.get("strong", True)
        elif t == "ghost_forward":
            p["ghosts"].add(d.get("ghost"))
        elif t == "bait_forward":
            p["bfwd"].add(d.get("victim"))
            p["victims"].add(d.get("victim"))
            p["kept"] = p["kept"] or bool(d.get("kept_share"))
        elif t == "token_spender_pull":
            p["tsp"].add(d.get("victim"))
            p["victims"].add(d.get("victim"))
        elif t == "owner_takeover":
            p["takeovers"].add(d.get("contract"))
            p["victims"].add(d.get("victim"))
        elif t == "safe_approval":
            p["safe_app"].add(d.get("victim"))
        elif t == "safe_pull":
            p["safe_pull"].add(d.get("victim"))
        elif t == "seaport_zero":
            p["sz"].add(d.get("victim"))
            p["victims"].add(d.get("victim"))
        elif t in ("nft_operator_pull", "batch7702_approve"):
            p["victims"].add(d.get("victim"))
        elif t == "eip7702_batch":
            p["a7702"] = True
            p["a7702_c0"] = p["a7702_c0"] or bool(d.get("chain0"))
        if t in ("split_pull", "split_xtx") and not d.get("spoof") and d.get("recipients"):
            p["grid"] = p["grid"] or bool(wrules.grid_share(d["recipients"][0].get("share")))
        if t == "bait_payable" and d.get("claimer_shape"):
            p["claimer"] = True

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
    from .exposure import ONESHOT_MAX_NONCE, ensure_tables
    ensure_tables(conn)
    fresh_eoas = {(r["chain"], r["address"]) for r in conn.execute(
        "SELECT s.chain,s.address FROM subject_info s JOIN codes k ON k.chain=s.chain AND k.address=s.address "
        "WHERE s.nonce <= ? AND k.size = 0", (ONESHOT_MAX_NONCE,))}
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
        # kit notes N1-N11
        if p["kit_public"] or addr in KIT_PUBLIC_CONTRACTS:
            lb.add("kit_public")                  # N2: exact runtime of a kit public contract (or its address)
        if "bait_payable" in p["types"] and (p["bait_public"] or "kit_public" in lb):
            lb.add("kit_confirmed")               # N3: a bait victim of a kit public contract
        if p["cashback"]:
            lb.add("ms_cashback")
        elif p["cashback_shape"]:
            lb.add("ms_cashback_shape")
        if p["dust"]:
            lb.add("dust_approve")
            if any(d.get("kit") for d in p["dust"]):
                lb.add("dust_approve_kit")
        if any(not d.get("self_approval") for d in p["egas"]):
            lb.add("emergency_gas")
        elif p["egas"]:
            lb.add("emergency_gas_self")          # self-approval only: T3 lead (custodial sweep shape)
        if p["egas"]:
            if any(d.get("kit") for d in p["egas"]):
                lb.add("emergency_gas_kit")
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
        # TRON rules T-1..T-8
        if "kit_pull" in p["types"]:
            lb.add("kit_pull")
        for kind, label in (("kit_amount", "approval_kit_shape"), ("approve_all", "approve_all_call"),
                            ("aml_exact", "aml_approve_transfer"), ("increase_max", "increase_max")):
            if kind in p["tron_kinds"]:
                lb.add(label)
        if p["prefund"]:
            lb.add("prefund_approve")
            by_amt = defaultdict(set)
            for v, amt in p["prefund"]:
                by_amt[amt].add(v)
            if any(len(vs) >= TRON_PREFUND_T2 for vs in by_amt.values()):
                lb.add("prefund_approve_multi")
        if p["claimer"]:
            lb.add("claimer_split")
        if p["hijack"]:
            lb.add("perm_hijack")
            if len(p["hijack"]) >= TRON_PERM_T2:
                lb.add("perm_hijack_multi")
        if "perm_hijack_drain" in p["types"]:
            lb.add("perm_hijack_drain")
        if p["fees"]:
            by_amt = defaultdict(lambda: (set(), set()))
            for amt, v, ptx in p["fees"]:
                by_amt[amt][0].add(v)
                by_amt[amt][1].add(ptx)
            if any(len(txs) >= TRON_FEE_MIN_HITS for _, txs in by_amt.values()):
                lb.add("fixed_fee")
                if any(len(vs) >= 3 for vs, _ in by_amt.values()):
                    lb.add("fixed_fee_multi")
        if p["poison"]:
            lb.add("poison_zero")
        if "approval_fingerprint" in p["types"] and (chain, addr) in fresh_eoas:
            lb.add("oneshot_spender")             # MS Drainer Wallet Randomizer: fresh EOA spender of kit approvals
        # web-research rules W1-W11
        for t in ("nft_operator_pull", "batch7702_approve"):
            if t in p["types"]:
                lb.add(t)
        if "deploy_drain" in p["types"]:            # strong: nothing back to the victim, tokens ended at an EOA
            lb.add("deploy_drain" if p["dd_strong"] else "deploy_drain_weak")
        if p["ghosts"]:
            lb.add("ghost_forward")
            if len(p["ghosts"]) >= 2:
                lb.add("ghost_forward_multi")      # code that existed only inside the tx moved tokens of 2+ addresses
        if p["bfwd"]:
            lb.add("bait_forward")
            if len(p["bfwd"]) >= 2:
                lb.add("bait_forward_multi")
        if p["kept"]:
            lb.add("kept_share")
        if p["tsp"]:
            lb.add("token_spender_pull")
            if len(p["tsp"]) >= 2:
                lb.add("token_spender_multi")
        if p["takeovers"]:
            lb.add("owner_takeover")
            if len(p["takeovers"]) >= 2:
                lb.add("owner_takeover_multi")
        if len(p["safe_app"]) >= 3:
            lb.add("safe_spender")
            if p["safe_pull"]:
                lb.add("safe_spender_pull")
        if p["sz"]:
            lb.add("seaport_zero")
            if len(p["sz"]) >= 2:
                lb.add("seaport_zero_multi")
        if p["a7702"]:
            lb.add("eip7702_batch")
            if p["a7702_c0"]:
                lb.add("eip7702_chain0")
        if p["grid"]:
            lb.add("share_grid")
        if wrules.is_vanity(addr) and (len(p["vapp"]) >= VANITY_MIN_APPROVERS or lb & VANITY_BEHAVIOUR):
            lb.add("vanity_drainer")
            p["victims"] |= p["vapp"]
        if KIT_VANITY_RE.match(addr) and (p["kit"] or p["kit_public"] or p["xchain"]):
            lb.add("kit_vanity")                  # N9: score booster with a kit fingerprint / K14 twin, never alone
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
        if tier in ("T1", "T2") and lb & UNPRICED_CAPPABLE and len(victims) == 1 and not usd \
                and not lb - UNPRICED_CAPPABLE - UNPRICED_NEUTRAL:
            tier = "T3"                    # one victim, nothing priced, no other evidence: token fee/tax router shape
            lb.add("unpriced_capped")
        if chain == "tron" and tier in ("T1", "T2") and lb & {"split_pull", "split_xtx"} and len(victims) < 3                 and not lb & {"kit_signature", "owner_gated_puller", "kit_pull", "family_match", "seed"}:
            tier = "T3"                    # TRON has no source verification here: payment splitters / forwarders look the same
            lb.add("tron_split_capped")
        if chain not in ("eth", "tron") and tier in ("T1", "T2") and lb & {"split_pull", "split_xtx"} \
                and len(victims) < 2 and not lb & UNVERIFIED_SPLIT_KEEP:
            tier = "T3"                    # no source verification on this chain (our Etherscan plan): a one-victim split
            lb.add("unverified_split_capped")   # needs a kit fingerprint, a kit share (W11) or other behaviour for T2
        c = codes.get((chain, addr))
        ts = p["ts"] or [now]
        src = seeds.get(chain, addr)[1] if "seed" in lb else "detector"
        rows.append(dict(chain=chain, address=addr, tier=tier, score=score_of(lb, len(victims), usd, active),
                         source=src, family=p["fam"] or p["kit"] or ("ms_oneshot_spender" if "oneshot_spender" in lb else None),
                         labels=sorted(lb), first=min(ts), last=max(ts),
                         victims=len(victims), drains=n_dr, usd=round(usd, 2),
                         code_hash=c["code_hash"] if c else None, size=c["size"] if c else None,
                         is_contract=(1 if c["size"] else 0) if c else None, skeleton=c["skeleton"] if c else None,
                         verified=None if not vf or vf["verified"] is None else int(vf["verified"]),
                         contract_name=vf["name"] if vf else None))

    cross_chain_rows(rows)
    operator_wallets(conn, rows, labels, allow, codes)
    serial_deployers(conn, rows, labels, allow, codes)
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


def _own_strong(r):
    """Own T1/T2 with behavioural (non-static) evidence: independent of cluster inheritance and W12/W13 themselves."""
    lb = set(r["labels"])
    return r["tier"] in ("T1", "T2") and bool(lb - STATIC_LABELS - {"cluster_inherited", "operator_wallet",
                                                                    "operator_wallet_multi", "serial_deployer",
                                                                    "serial_deployer_multi", "verified_capped"})


def _add_subject(rows, by_key, chain, addr, label_set, tier, codes, extra_victims=0):
    """Add W12/W13 labels to an existing row (re-tiering never lowers it) or create a row for the wallet."""
    r = by_key.get((chain, addr))
    if r:
        lb = set(r["labels"]) | label_set
        new = assign_tier(lb, r["victims"], True)
        r["labels"] = sorted(lb)
        if new and TIER_RANK[new] < TIER_RANK[r["tier"]]:
            r["tier"] = new
        r["score"] = max(r["score"], score_of(lb, r["victims"], r["usd"], True))
        return
    c = codes.get((chain, addr))
    r = dict(chain=chain, address=addr, tier=tier, score=score_of(label_set, extra_victims, 0, True), source="detector",
             family=None, labels=sorted(label_set), first=now_ts(), last=now_ts(), victims=extra_victims, drains=0,
             usd=0.0, code_hash=c["code_hash"] if c else None, size=c["size"] if c else None,
             is_contract=(1 if c["size"] else 0) if c else None, skeleton=c["skeleton"] if c else None, verified=None,
             contract_name=None)
    rows.append(r)
    by_key[(chain, addr)] = r


def operator_wallets(conn, rows, labels, allow, codes):
    """W12 fee / operator wallet: an address (not a known contract, not legitimate) recorded as payout wallet
    (split share, customer, collector, receiver, kit fee) of >= 2 distinct flagged drainers -> `operator_wallet` (T3);
    >= OPERATOR_WALLET_T2 drainers with their OWN behavioural T1/T2 -> `operator_wallet_multi` (T2). Mutates rows."""
    by_key = {(r["chain"], r["address"]): r for r in rows}
    per = defaultdict(set)
    for p in conn.execute("SELECT chain,drainer,wallet,role FROM payouts WHERE role NOT IN ('deployer','worker','submitter')"):
        if (p["chain"], p["drainer"]) in by_key and p["wallet"] != p["drainer"]:
            per[(p["chain"], p["wallet"])].add(p["drainer"])
    for (chain, w), drs in per.items():
        if len(drs) < 2 or is_legit_subject(chain, w, labels, allow=allow):
            continue
        c = codes.get((chain, w))
        if c and c["size"]:
            continue
        strong = [d for d in drs if _own_strong(by_key[(chain, d)])]
        lb = {"operator_wallet"} | ({"operator_wallet_multi"} if len(strong) >= OPERATOR_WALLET_T2 else set())
        _add_subject(rows, by_key, chain, w, lb, "T2" if "operator_wallet_multi" in lb else "T3", codes)


def serial_deployers(conn, rows, labels, allow, codes):
    """W13 serial deployer: >= 2 flagged contracts (behavioural evidence) from one deployer / factory ->
    `serial_deployer` (T3); >= SERIAL_DEPLOYER_T2 with their own behavioural T1/T2 -> `serial_deployer_multi` (T2).
    Deployers: top-level creations, resolved deployers (Etherscan) and W1 deploy-and-drain evidence."""
    by_key = {(r["chain"], r["address"]): r for r in rows}
    dep = defaultdict(set)
    for q, cols in (("SELECT chain,address,deployer FROM creations", ("deployer",)),
                    ("SELECT chain,address,deployer,factory FROM contract_deployer", ("deployer", "factory"))):
        for r in conn.execute(q):
            for col in cols:
                if r[col] and (r["chain"], r["address"]) in by_key:
                    dep[(r["chain"], r[col])].add(r["address"])
    for r in conn.execute("SELECT chain,address,detail FROM evidence WHERE type='deploy_drain'"):
        d = json.loads(r["detail"] or "{}")
        k = d.get("deployer") or (d.get("factory") if d.get("role") != "factory" else None)
        if k and (r["chain"], r["address"]) in by_key:
            dep[(r["chain"], k)].add(r["address"])
    for (chain, k), contracts in dep.items():
        contracts = {c for c in contracts if c != k and set(by_key[(chain, c)]["labels"]) - STATIC_LABELS}
        if len(contracts) < 2 or is_legit_subject(chain, k, labels, allow=allow):
            continue
        strong = [c for c in contracts if _own_strong(by_key[(chain, c)])]
        lb = {"serial_deployer"} | ({"serial_deployer_multi"} if len(strong) >= SERIAL_DEPLOYER_T2 else set())
        _add_subject(rows, by_key, chain, k, lb, "T2" if "serial_deployer_multi" in lb else "T3", codes)


def cross_chain_rows(rows):
    """K14 / S6: the same address flagged on >= 2 chains with the same opcode skeleton (same deployer + nonce, same
    code) is one operator's reuse: label `cross_chain` on every twin, `cross_chain_t1` (T2) on twins of a T1. Uses own
    tiers only. Mutates rows in place."""
    by_addr = defaultdict(list)
    for r in rows:
        if r["skeleton"] and (r["size"] or 0) >= 100 and "verified_capped" not in r["labels"]:
            by_addr[(r["address"], r["skeleton"])].append(r)
    # a twin counts as T1 only on its own uncapped evidence
    for g in by_addr.values():
        for r in g:
            r["_own"] = r["tier"]
    for group in by_addr.values():
        if len({r["chain"] for r in group}) < 2:
            continue
        own = {r["chain"]: r["_own"] for r in group}
        for r in group:
            lb = set(r["labels"]) | {"cross_chain"}
            if any(t == "T1" for c, t in own.items() if c != r["chain"]):
                lb.add("cross_chain_t1")
            r["labels"] = sorted(lb)
            if lb & CAPPED_LABELS:
                continue                   # its own evidence was capped: a twin never re-raises it
            new = assign_tier(lb, r["victims"], True)
            if new == "T1" and not (lb - STATIC_LABELS - {"cluster_inherited"}):
                new = "T2"                 # no own behavioural evidence: a twin lifts it to T2 at most
            if new and TIER_RANK[new] < TIER_RANK[r["tier"]]:
                r["tier"] = new
    for r in rows:
        r.pop("_own", None)


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
            if TIER_RANK[own[k]] <= best or set(r["labels"]) & CAPPED_LABELS:
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
