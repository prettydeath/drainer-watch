"""Scan wiring of the web-research rules W1-W13 (pure parts in wrules.py). Called from scan.process_chunk (every chunk;
most rules need the receipts source: tx.from / tx.to of every tx and the extra receipt topics) and from
scan.eth_block_pass (W3 bait forwarding, W8a batch authorizations). Rollup-level rules W11-W13 live in rollup.py."""
import logging
from collections import defaultdict

from . import enrich, wrules
from .constants import (AUTH_BATCH_MIN, BAIT_FORWARD_MAX_LOOKUPS, BAIT_FORWARD_MIN, CHAINS, DEPLOY_DRAIN_MAX_LOOKUPS,
                        LEGIT_7702_DELEGATES, MIN_USD, NFT_OPERATOR_WINDOW_SEC, POISON_MIN_LEGS, POISON_WINDOW_SEC,
                        STABLES, TAKEOVER_MAX_NEW_OWNER_NONCE, TAKEOVER_WINDOW_SEC, ZERO)
from .detectors import redemption_like
from .tokens import fmt_amount

log = logging.getLogger("drainerwatch.wscan")

MAX_GHOST_NONCES = 150
MAX_SPENDER_CODES = 150


def _blocks(ctx, sec):
    return max(1, int(sec / CHAINS[ctx.chain].get("block_sec", 12)))


def _state(ctx):
    if not hasattr(ctx, "w"):
        ctx.w = dict(takeover=[], nftops={}, cp=defaultdict(dict), es=None, created={}, fwd_lookups=0, dd_lookups=0)
    return ctx.w


def etherscan(ctx):
    """Lazily created Etherscan client (None without keys); per-run caps live in the callers."""
    st = _state(ctx)
    if st["es"] is None:
        es = enrich.Etherscan(calls_cap=DEPLOY_DRAIN_MAX_LOOKUPS + BAIT_FORWARD_MAX_LOOKUPS)
        st["es"] = es if es.enabled and ctx.chain in CHAINS and CHAINS[ctx.chain].get("id") else False
    return st["es"] or None


def priced_ok(ctx, legs):
    """False when every leg is priced and the sum is below MIN_USD; True otherwise (unpriced counts as unknown)."""
    usd = [ctx.prices.usd(ctx.chain, x["token"], x["value"], ctx.tokens.get(x["token"])[1]) for x in legs]
    return not (all(u is not None for u in usd) and sum(usd) < MIN_USD)


def is_eoa(ctx, addr):
    """Known to have no code (or only an EIP-7702 delegation designator)."""
    return addr in ctx.code_hex and not ctx.is_contract(addr)


# ---------- entry point ----------
def web_chunk(ctx, logs, tr, ap, txmeta=None):
    ex = wrules.parse_extra(logs)
    ctx.chunk_ex = ex
    for fn, args in ((vanity_approvals, (ap, ex["p2"])), (seaport, (ex["seaport"],))):
        _safe(ctx, fn, *args)
    if not ctx.full_txs:
        return
    for fn, args in ((deploy_drain, (tr, ap, txmeta or {})), (ghost_forward, (tr, ap, ex["auth_txs"])),
                     (token_spender, (tr,)), (takeover, (ex["owner"], tr)), (safe_spender, (tr, ap, ex["p2"])),
                     (nft_operator, (ap, ex["nft"])), (batch7702, (tr, ap)), (poison_zero, (tr,))):
        _safe(ctx, fn, *args)


def _safe(ctx, fn, *args):
    try:
        fn(ctx, *args)
    except Exception as e:  # noqa: BLE001 - one rule failing must not break the chunk
        ctx.stats["w_errors"] += 1
        log.warning("%s: %s failed: %s", ctx.chain, fn.__name__, e)


# ---------- W2 vanity spenders ----------
def vanity_approvals(ctx, ap, p2):
    """Approvals / ApprovalForAll / Permit2 permits to a vanity-address spender: evidence `vanity_approval` (the
    approver as victim, EOA owners only) and the approval is stored so D3 / W4 see later pulls."""
    cands = [a for a in list(ap) + list(p2) if a["value"] > 0 and wrules.is_vanity(a["spender"])
             and a["owner"] != a["spender"] and not ctx.is_allowed(a["spender"])]
    if not cands:
        return
    ctx.ensure_codes([a["owner"] for a in cands])
    ts = ctx.ts_of([b for b in {a["block"] for a in cands}])
    for a in cands:
        if not is_eoa(ctx, a["owner"]):
            continue
        ctx.emit("vanity_approval", a["spender"], a["tx"], a["block"], dict(victim=a["owner"], token=a["token"],
                                                                            kind=a.get("kind", "approval")))
        ctx.conn.execute("INSERT OR IGNORE INTO approvals(chain,owner,spender,token,tx,block,ts) VALUES(?,?,?,?,?,?,?)",
                         (ctx.chain, a["owner"], a["spender"], a["token"], a["tx"], a["block"], ts.get(a["block"])))
        ctx.owner_spenders[a["owner"]].add(a["spender"])
        ctx.stats["w2_vanity_approval"] += 1


# ---------- W1 deploy-and-drain ----------
def deploy_drain(ctx, tr, ap, txmeta):
    st = _state(ctx)
    for h in txmeta:
        if txmeta[h].get("created"):
            st["created"][txmeta[h]["created"]] = h
    # W1a: top-level creation that moves a third party's tokens in its own tx
    hits = wrules.toplevel_deploy_drain(tr, txmeta)
    if hits:
        ctx.ensure_codes([x["frm"] for hh in hits for x in hh["legs"]])
        ctx.tokens.ensure({x["token"] for hh in hits for x in hh["legs"]})
    for hh in hits:
        c = hh["created"]
        legs = [x for x in hh["legs"] if not ctx.tokens.is_spoof(x["token"]) and is_eoa(ctx, x["frm"])
                and not ctx.is_allowed(x["frm"])]
        if not legs or ctx.is_allowed(c) or not priced_ok(ctx, legs):
            continue
        det = dict(via="toplevel", deployer=hh["deployer"], victims=sorted({x["frm"] for x in legs}),
                   tokens=sorted({x["token"] for x in legs}), **drain_shape(ctx, tr, hh["tx"], legs, c))
        if _emit_drain(ctx, "deploy_drain", c, hh["tx"], hh["block"], det, legs):
            from .scan import add_payout
            add_payout(ctx.conn, ctx.chain, c, hh["deployer"], "deployer")
        ctx.stats["w1_deploy_drain"] += 1
    # W1b: permit executed and used in one tx by a spender that had no code before that tx
    cands = wrules.permit_pull_candidates(tr, ap, ctx.txs, ctx.is_allowed)
    cands = [c for c in cands if (txmeta.get(c["tx"]) or {}).get("created") != c["spender"]]
    if not cands:
        return
    ctx.tokens.ensure({x["token"] for c in cands for x in c["legs"]})
    ctx.ensure_codes([c["victim"] for c in cands])
    cands = [c for c in cands if is_eoa(ctx, c["victim"]) and any(not ctx.tokens.is_spoof(x["token"]) for x in c["legs"])]
    for c in cands:
        new = created_in_tx(ctx, c["spender"], c["tx"], c["block"])
        if not new:
            continue
        legs = [x for x in c["legs"] if not ctx.tokens.is_spoof(x["token"])]
        if not priced_ok(ctx, legs):
            continue
        det = dict(via="factory", factory=c["tx_to"], child=c["spender"], caller=c["tx_from"], victims=[c["victim"]],
                   tokens=sorted({x["token"] for x in legs}), created_check=new,
                   **drain_shape(ctx, tr, c["tx"], legs, c["spender"]))
        _emit_drain(ctx, "deploy_drain", c["spender"], c["tx"], c["block"], det, legs)
        if c["tx_to"] != c["spender"] and not ctx.is_allowed(c["tx_to"]):
            ctx.emit("deploy_drain", c["tx_to"], c["tx"], c["block"], dict(det, role="factory"))
        ctx.stats["w1_factory_drain"] += 1


def drain_shape(ctx, tr, h, legs, child):
    """W1 strength: the victim got nothing back in the tx (no Transfer / mint to it) and its tokens ended at an EOA
    other than the victim (directly, or forwarded by the new contract). Legitimate counterparts (smart-account onboarding,
    flash-loan adapters, collateral swaps) return something or keep the tokens in contracts. Returns detail fields."""
    victims = {x["frm"] for x in legs}
    tokens = {x["token"] for x in legs}
    txl = [t for t in tr if t["tx"] == h and t["value"] > 0]
    back = any(t["to"] in victims for t in txl)
    outs = sorted({t["to"] for t in txl if t["token"] in tokens and t["frm"] in victims | {child}
                   and t["to"] not in victims | {child, ZERO}})
    ctx.ensure_codes(outs[:20])
    eoa_out = [o for o in outs[:20] if is_eoa(ctx, o) and not ctx.is_allowed(o)]
    return dict(returned=back, eoa_out=eoa_out[:5], strong=not back and bool(eoa_out))


def created_in_tx(ctx, addr, tx, block):
    """'archive' when the node says addr had no code at block - 1, 'etherscan' when its creation tx is `tx`,
    None when it existed before or nothing can tell (no recent state, no Etherscan key, lookup cap reached)."""
    st = _state(ctx)
    if st["created"].get(addr) == tx:
        return "toplevel"
    fn = getattr(ctx.rpc, "code_at", None)
    if fn is not None:
        try:
            before = fn([(addr, block - 1)]).get((addr, block - 1))
        except Exception:  # noqa: BLE001
            before = None
        if before is not None:
            return "archive" if before in ("0x", "") else None
    es = etherscan(ctx)
    if es is None or st["dd_lookups"] >= DEPLOY_DRAIN_MAX_LOOKUPS:
        ctx.stats["w1_unknown"] += 1
        return None
    st["dd_lookups"] += 1
    res = es.call(ctx.chain, dict(module="contract", action="getcontractcreation", contractaddresses=addr))
    if res and (res[0].get("txHash") or "").lower() == tx.lower():
        return "etherscan"
    return None


def _emit_drain(ctx, type_, subject, tx, block, det, legs, victim=None):
    from .scan import add_evidence_pending
    new = add_evidence_pending(ctx, type_, subject, tx, block, det)
    for x in legs:
        ctx.pdr.append(ctx.drain_row(x, victim or x["frm"], subject))
    return new


# ---------- W1c ghost forwarder ----------
def ghost_forward(ctx, tr, ap, auth_txs):
    cands = wrules.ghost_candidates(tr, ap, ctx.txs, auth_txs, ctx.is_allowed)
    if not cands:
        return
    ctx.tokens.ensure({x["token"] for legs in cands.values() for x in legs})
    keep = {}
    for k, legs in cands.items():
        legs = [x for x in legs if not ctx.tokens.is_spoof(x["token"]) and
                (ctx.prices.usd(ctx.chain, x["token"], x["value"], ctx.tokens.get(x["token"])[1]) or 0) >= MIN_USD]
        if legs:
            keep[k] = legs            # priced legs only: spam tokens emit Transfer events from arbitrary addresses
    need = list(dict.fromkeys(c for (_, c) in keep if c not in ctx.nonce))
    ctx.stats["w1_ghost_truncated"] += max(0, len(need) - MAX_GHOST_NONCES)
    if need[:MAX_GHOST_NONCES]:
        ctx.stats["nonce_lookups"] += len(need[:MAX_GHOST_NONCES])
        ctx.nonce.update(ctx.rpc.nonces(need[:MAX_GHOST_NONCES]))
    zero = [k for k in keep if ctx.nonce.get(k[1]) == 0]
    if not zero:
        return
    ctx.ensure_codes([c for _, c in zero] + [to for to, _ in zero])
    for to, c in zero:
        if ctx.code_hex.get(c) not in ("0x", "") or ctx.is_allowed(to):
            continue
        legs = keep[(to, c)]
        det = dict(ghost=c, caller=ctx.txs[legs[0]["tx"]]["from"], tokens=sorted({x["token"] for x in legs}),
                   recipients=sorted({x["to"] for x in legs}),
                   amounts=[dict(token=x["token"], amount=fmt_amount(x["value"], ctx.tokens.get(x["token"])[1]))
                            for x in legs[:5]])
        ctx.emit("ghost_forward", to, legs[0]["tx"], legs[0]["block"], det)
        ctx.stats["w1_ghost_forward"] += 1


# ---------- W4 token-like spender with DELEGATECALL ----------
def token_spender(ctx, tr):
    mb = defaultdict(list)
    for t in tr:
        if (t["frm"] == ZERO) != (t["to"] == ZERO) and t["value"] > 0:
            mb[t["tx"]].append(t)
    cands = []
    for t in tr:
        tx = ctx.txs.get(t["tx"])
        if not tx or not tx.get("to") or t["value"] == 0 or ZERO in (t["frm"], t["to"]):
            continue
        s = tx["to"]
        if t["frm"] in (tx["from"], s) or t["token"] == s or t["to"] == s or ctx.is_allowed(s) or ctx.is_allowed(t["frm"]):
            continue
        cands.append(t)
    if not cands:
        return
    ctx.ensure_codes([ctx.txs[t["tx"]]["to"] for t in cands], cap=MAX_SPENDER_CODES)
    hits = []
    for t in cands:
        s = ctx.txs[t["tx"]]["to"]
        info = ctx.analysis(s)
        if info and info.get("erc20_like") and info.get("delegatecall") and not redemption_like(mb.get(t["tx"]), s, [t["to"]]):
            hits.append((t, s))
    if not hits:
        return
    ctx.ensure_codes([t["frm"] for t, _ in hits])
    ctx.tokens.ensure({t["token"] for t, _ in hits})
    from .scan import add_payout
    for t, s in hits:
        if not is_eoa(ctx, t["frm"]) or ctx.tokens.is_spoof(t["token"]) or not priced_ok(ctx, [t]):
            continue
        det = dict(victim=t["frm"], caller=ctx.txs[t["tx"]]["from"], recipient=t["to"], token=t["token"])
        if _emit_drain(ctx, "token_spender_pull", s, t["tx"], t["block"], det, [t]):
            add_payout(ctx.conn, ctx.chain, s, t["to"], "collector")
        ctx.d5(s, t["tx"], t["block"])
        ctx.stats["w4_token_spender"] += 1


# ---------- W5 owner takeover ----------
def takeover(ctx, events, tr):
    st = _state(ctx)
    pend = wrules.owner_changes(events, ctx.txs)
    if pend:
        ctx.ensure_codes([p["contract"] for p in pend] + [p["new_owner"] for p in pend])
        for p in pend:
            if ctx.is_contract(p["contract"]) and is_eoa(ctx, p["new_owner"]) and not ctx.is_allowed(p["new_owner"]) \
                    and not ctx.is_allowed(p["contract"]):
                st["takeover"].append(p)
    if not st["takeover"]:
        return
    last = max((t["block"] for t in tr), default=None)
    if last is not None:
        st["takeover"] = [p for p in st["takeover"] if p["block"] >= last - _blocks(ctx, TAKEOVER_WINDOW_SEC)]
    hits = wrules.takeover_hits(st["takeover"], tr, ctx.txs)
    if not hits:
        return
    need = [p["new_owner"] for p, _ in hits if p["new_owner"] not in ctx.nonce]
    if need:
        ctx.nonce.update(ctx.rpc.nonces(need))
    ctx.tokens.ensure({x["token"] for _, legs in hits for x in legs})
    for p, legs in hits:
        n = ctx.nonce.get(p["new_owner"])
        legs = [x for x in legs if not ctx.tokens.is_spoof(x["token"])]
        if n is None or n > TAKEOVER_MAX_NEW_OWNER_NONCE or not legs or not priced_ok(ctx, legs):
            continue
        victim = p["prev"] if p["prev"] not in (None, ZERO) else p["signer"]
        det = dict(victim=victim, contract=p["contract"], kind=p["kind"], change_tx=p["change_tx"], signer=p["signer"],
                   new_owner_nonce=n, outflow_txs=sorted({x["tx"] for x in legs})[:5],
                   tokens=sorted({x["token"] for x in legs}), removed=p.get("removed"), threshold=p.get("threshold"))
        _emit_drain(ctx, "owner_takeover", p["new_owner"], legs[0]["tx"], legs[0]["block"], det, legs, victim=victim)
        ctx.stats["w5_owner_takeover"] += 1


# ---------- W6 Safe proxy as spender ----------
def safe_spender(ctx, tr, ap, p2):
    aps = [a for a in list(ap) + list(p2) if a["value"] > 0 and a.get("kind") != "all"
           and a["spender"] not in (ZERO, a["owner"]) and not ctx.is_allowed(a["spender"])]
    if aps:
        ctx.ensure_codes([a["spender"] for a in aps], cap=MAX_SPENDER_CODES)
    safes = {a["spender"] for a in aps if (ctx.analysis(a["spender"]) or {}).get("safe_proxy")}
    pulls = []
    for t in tr:
        tx = ctx.txs.get(t["tx"])
        if tx and tx.get("to") and t["value"] > 0 and t["frm"] not in (tx["from"], tx["to"], ZERO) \
                and (tx["to"] in safes or tx["to"] in ctx.code_hex and (ctx.analysis(tx["to"]) or {}).get("safe_proxy")) \
                and not ctx.is_allowed(tx["to"]):
            pulls.append(t)
    if not safes and not pulls:
        return
    ctx.ensure_codes([a["owner"] for a in aps if a["spender"] in safes] + [t["frm"] for t in pulls])
    for a in aps:
        if a["spender"] in safes and is_eoa(ctx, a["owner"]):
            ctx.emit("safe_approval", a["spender"], a["tx"], a["block"], dict(victim=a["owner"], token=a["token"],
                                                                              kind=a.get("kind", "approval")))
            ctx.stats["w6_safe_approval"] += 1
    if pulls:
        ctx.tokens.ensure({t["token"] for t in pulls})
    for t in pulls:
        s = ctx.txs[t["tx"]]["to"]
        if not is_eoa(ctx, t["frm"]) or ctx.tokens.is_spoof(t["token"]) or not priced_ok(ctx, [t]):
            continue
        _emit_drain(ctx, "safe_pull", s, t["tx"], t["block"], dict(victim=t["frm"], recipient=t["to"], token=t["token"],
                                                                   caller=ctx.txs[t["tx"]]["from"]), [t])
        ctx.stats["w6_safe_pull"] += 1


# ---------- W7 NFT ----------
def seaport(ctx, evs):
    hits = [(e, d) for e in evs for d in [wrules.seaport_zero(e)] if d and not ctx.is_allowed(d["fulfiller"])]
    if not hits:
        return
    ctx.ensure_codes([d["victim"] for _, d in hits])
    for e, d in hits:
        if not is_eoa(ctx, d["victim"]):
            continue
        ctx.emit("seaport_zero", d["fulfiller"], e["tx"], e["block"], dict(d, zone=e["zone"], seaport=e["contract"]))
        ctx.stats["w7_seaport_zero"] += 1


def nft_operator(ctx, ap, nft):
    st = _state(ctx)
    ops = [a for a in ap if a["kind"] == "all" and a["value"] > 0 and a["spender"] not in (ZERO, a["owner"])
           and not ctx.is_allowed(a["spender"])]
    if ops:
        ctx.ensure_codes([a["spender"] for a in ops])
        for a in ops:
            if is_eoa(ctx, a["spender"]):
                st["nftops"][(a["owner"], a["spender"])] = (a["tx"], a["block"])
    if not st["nftops"]:
        return
    last = max([t["block"] for t in nft] + [a["block"] for a in ap], default=None)
    if last is not None:
        lim = last - _blocks(ctx, NFT_OPERATOR_WINDOW_SEC)
        st["nftops"] = {k: v for k, v in st["nftops"].items() if v[1] >= lim}
    for (op, owner), legs in wrules.nft_operator_pulls(st["nftops"], nft, ctx.txs).items():
        ctx.emit("nft_operator_pull", op, legs[0]["tx"], legs[0]["block"], dict(
            victim=owner, approval_tx=st["nftops"][(owner, op)][0], n_nfts=len(legs),
            nfts=[dict(token=x["token"], ident=str(x["ident"]), to=x["to"]) for x in legs[:10]]))
        ctx.stats["w7_nft_operator"] += 1


# ---------- W8b phishing batch through a delegated EOA ----------
def batch7702(ctx, tr, ap):
    selfcalls = {h for h in {x["tx"] for x in list(tr) + list(ap)}
                 if (ctx.txs.get(h) or {}).get("to") and ctx.txs[h]["to"] == ctx.txs[h]["from"]}
    if not selfcalls:
        return
    ctx.ensure_codes([ctx.txs[h]["from"] for h in selfcalls])
    selfcalls = {h for h in selfcalls if ctx.is_delegated(ctx.txs[h]["from"])}
    trs, aps = defaultdict(list), defaultdict(list)
    for t in tr:
        if t["tx"] in selfcalls:
            trs[t["tx"]].append(t)
    for a in ap:
        if a["tx"] in selfcalls:
            aps[a["tx"]].append(a)
    for h in selfcalls:
        owner = ctx.txs[h]["from"]
        res = wrules.batch7702_tx(owner, aps[h], trs[h], ctx.is_allowed)
        if not res:
            continue
        ctx.ensure_codes(res["spenders"] + res["recipients"])
        delegate = "0x" + ctx.code_hex[owner][8:48].lower()
        blk = (trs[h] or aps[h])[0]["block"]
        for sp in res["spenders"]:
            if not is_eoa(ctx, sp):
                continue
            det = dict(victim=owner, delegate=delegate, legit_delegate=LEGIT_7702_DELEGATES.get(delegate),
                       approvals=res["approvals"], legs=res["legs"], recipients=res["recipients"])
            legs = [t for t in trs[h] if t["frm"] == owner and t["to"] == sp and t["value"] > 0]
            _emit_drain(ctx, "batch7702_approve", sp, h, blk, det, legs)
            ctx.stats["w8_batch7702"] += 1


# ---------- W10 zero-value poisoning ----------
def poison_zero(ctx, tr):
    st = _state(ctx)
    stables = STABLES.get(ctx.chain, set())
    cp = st["cp"]
    for t in tr:                                   # recent real counterparties of every stablecoin sender / receiver
        if t["value"] > 0 and t["token"] in stables:
            cp[t["frm"]][t["to"]] = t["block"]
            cp[t["to"]][t["frm"]] = t["block"]
    last = max((t["block"] for t in tr), default=None)
    if last is None:
        return
    lim = last - _blocks(ctx, POISON_WINDOW_SEC)
    if len(cp) > 50_000 or (last % 20 == 0):
        for v in list(cp):
            cp[v] = {r: b for r, b in cp[v].items() if b >= lim}
            if not cp[v]:
                del cp[v]
    for subject, legs in wrules.zero_poison_legs(tr, ctx.txs, stables).items():
        if len(legs) < POISON_MIN_LEGS or ctx.is_allowed(subject):
            continue
        look = [x for x in legs if any(wrules.lookalike(r, x["to"]) for r, b in cp.get(x["frm"], {}).items() if b >= lim)]
        ctx.emit("poison_zero", subject, legs[0]["tx"], legs[0]["block"], dict(
            legs=len(legs), victims=len({x["frm"] for x in legs}), lookalikes=len(look), spoof=True,
            sample=[dict(victim=x["frm"], lookalike=x["to"]) for x in (look or legs)[:3]]))
        ctx.stats["w10_poison_zero"] += 1


# ---------- block pass hooks (ETH full blocks) ----------
def bait_forward(ctx, rows, ev_type="bait_forward"):
    """W3: value > 0 call with a bait selector (or any selector on a vanity-address contract) to contract code; the share
    of msg.value that left the contract to third addresses in the same tx: Etherscan internal transfers of that tx
    (capped per run), else the contract's balance delta over the block (recent state only; other txs of the block to
    the same contract are summed in). >= 95 % forwarded -> `bait_forward`; a documented DaaS share forwarded with the
    remainder kept (W11 'contract keeps the fee' variant) -> `bait_forward` with kept_share. Unknown -> nothing."""
    if not rows:
        return
    st = _state(ctx)
    ctx.ensure_codes([r[1] for r in rows])
    rows = [r for r in rows if ctx.is_contract(r[1]) and not ctx.is_allowed(r[1])]
    per_block = defaultdict(int)
    for h, to, sel, val, frm, bn, inp, meta in rows:
        per_block[(to, bn)] += val
    es = etherscan(ctx)
    from .scan import add_payout
    for h, to, sel, val, frm, bn, inp, meta in rows:
        share, receivers, via = None, [], None
        if es is not None and st["fwd_lookups"] < BAIT_FORWARD_MAX_LOOKUPS:
            st["fwd_lookups"] += 1
            res = es.call(ctx.chain, dict(module="account", action="txlistinternal", txhash=h))
            if res is not None:
                out = [r for r in res if (r.get("from") or "").lower() == to and (r.get("to") or "").lower() not in (to, frm)
                       and str(r.get("isError", "0")) == "0"]
                share = sum(int(r.get("value") or 0) for r in out) / val if val else None
                receivers = sorted({(r.get("to") or "").lower() for r in out if int(r.get("value") or 0) > 0})
                via = "internal_txs"
        if share is None:
            fn = getattr(ctx.rpc, "balances", None)
            if fn is not None:
                try:
                    b = fn([(to, bn - 1), (to, bn)])
                except Exception:  # noqa: BLE001
                    b = {}
                b0, b1 = b.get((to, bn - 1)), b.get((to, bn))
                if b0 is not None and b1 is not None and per_block[(to, bn)]:
                    share = max(0.0, 1 - (b1 - b0) / per_block[(to, bn)])
                    via = "balance_delta"
        if share is None:
            ctx.stats["w3_unknown"] += 1
            continue
        share = round(min(share, 1.0), 4)
        grid = wrules.grid_share(share)
        if share < BAIT_FORWARD_MIN and (not grid or ev_type != "bait_forward"):
            continue
        info = ctx.analysis(to) or {}
        det = dict(victim=frm, value_wei=str(val), selector=sel, in_dispatch=sel in (info.get("selectors") or []),
                   forwarded_share=share, via=via, receivers=receivers[:5], vanity=wrules.is_vanity(to))
        if grid and share < BAIT_FORWARD_MIN:
            det["kept_share"] = round(1 - grid, 2)
        from .scan import add_evidence_pending
        if add_evidence_pending(ctx, ev_type, to, h, bn, det):
            for r in receivers[:3]:
                add_payout(ctx.conn, ctx.chain, to, r, "receiver")
        price = ctx.prices.native.get(CHAINS[ctx.chain]["native"])
        ctx.pdr.append(dict(tx=h, li=-3, block=bn, victim=frm, drainer=to, token=ZERO, symbol=CHAINS[ctx.chain]["native"],
                            decimals=18, amount=fmt_amount(val, 18), usd=round(val / 1e18 * price, 2) if price else None,
                            recipient=receivers[0] if receivers else to))
        ctx.d5(to, h, bn)
        ctx.stats["w3_" + ev_type] += 1


def auth_batches(ctx, per_tx, chain0, first):
    """W8a: per_tx: delegate -> {tx: n authorizations}; chain0: delegate -> n with chainId 0; first: delegate ->
    (tx, block). A delegate receiving > 5 authorizations in one tx (not a known wallet implementation) -> evidence
    `eip7702_batch` (mass delegation of many keys in one tx: leaked-key sweeping)."""
    for d, txs in per_tx.items():
        mx = max(txs.values())
        if mx < AUTH_BATCH_MIN or d in LEGIT_7702_DELEGATES or ctx.is_allowed(d):
            continue
        h = max(txs, key=txs.get)
        ctx.emit("eip7702_batch", d, h, first[d][1], dict(max_per_tx=mx, txs=len(txs), authorizations=sum(txs.values()),
                                                          chain0=chain0.get(d, 0)))
        ctx.stats["w8_auth_batch"] += 1

