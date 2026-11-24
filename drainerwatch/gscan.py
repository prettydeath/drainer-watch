"""Scan wiring of the GitHub / paper research rules G1-G13 (pure parts in grules.py). g_chunk runs on every chunk after the
W rules (most rules need the receipts source); g_block runs inside the ETH full-block pass (calldata, value, nonce)."""
import logging
from collections import defaultdict

from . import bytecode, grules, wrules, wscan
from .constants import (BAIT_CAPTURE, CHAINS, FAKE_CALL_CONTRACT_MAX, FAKE_CALL_SELECTORS, FAKE_CALL_MAX_RECIPIENT_NONCE,
                        FAKE_CALL_MAX_SENDER_NONCE, FAKE_CALL_NEAR_BLOCKS, FULL_BALANCE_MAX_LOOKUPS,
                        FUNDERS_MAX_RECIPIENT_NONCE, FUNDERS_TRACK_MIN, FUNDERS_WINDOW_SEC, LEGIT_7702_DELEGATES,
                        LOOKALIKE_BUSY_MIN, MIN_USD, NFT_TRANSFER_HELPERS, PHISH_WITHDRAW_SELECTORS,
                        POISON_BATCH_MIN_LEGS, POISON_MIN_ATTACK_RATIO, POISON_TINY_MAX_USD,
                        STABLES, TRUSTED_ROUTERS, WRAPPED_NATIVE, ZERO, ZERO_NONCE_MAX_LOOKUPS,
                        ALLOWLIST, COUNTERFACTUAL_MAX_LOOKUPS)
from .tokens import fmt_amount
from .util import now_ts

log = logging.getLogger("drainerwatch.gscan")

PULL_EVIDENCE = {"eoa_spender_pull", "multi_victim_pull", "split_pull", "split_xtx", "owner_collect", "token_spender_pull",
                 "safe_pull", "router_sweep", "phish_multicall"}


def _safe(ctx, fn, *args):
    try:
        fn(ctx, *args)
    except Exception as e:  # noqa: BLE001 - one rule failing must not break the chunk
        ctx.stats["g_errors"] += 1
        log.warning("%s: %s failed: %s", ctx.chain, fn.__name__, e)


def _state(ctx):
    if not hasattr(ctx, "g"):
        ctx.g = dict(cf_lookups=0, fb_lookups=0, zn_lookups=0, fc_lookups=0)
    return ctx.g


def _emit(ctx, type_, subject, tx, block, det, legs=(), victim=None, role=None):
    from .scan import add_evidence_pending, add_payout
    new = add_evidence_pending(ctx, type_, subject, tx, block, det)
    for x in legs:
        ctx.pdr.append(ctx.drain_row(x, victim or x["frm"], subject))
    if new and role:
        for w in role[1]:
            add_payout(ctx.conn, ctx.chain, subject, w, role[0])
    return new


# ---------- per chunk ----------
def g_chunk(ctx, logs, tr, ap, txmeta=None):
    ex = getattr(ctx, "chunk_ex", None) or wrules.parse_extra(logs)
    _safe(ctx, seaport_fee, ex["seaport"])
    _safe(ctx, zero_nonce_approvals, ap)
    if not ctx.full_txs:
        _safe(ctx, full_balance, tr)
        return
    for fn, args in ((router_sweep, (tr,)), (nft_bulk, (ex["nft"],)), (poison_ext, (tr, ap, txmeta or {})),
                     (lookalike_contracts, (tr, txmeta or {})), (counterfactual, (tr, ap, ex["auth_txs"])),
                     (decoy_batch, (tr,)), (full_balance, (tr,))):
        _safe(ctx, fn, *args)


# ---------- G4 router pull + sweep ----------
def router_sweep(ctx, tr):
    hits = grules.router_sweeps(tr, ctx.txs, TRUSTED_ROUTERS)
    if not hits:
        return
    ctx.ensure_codes([r for h in hits for r in h["recipients"]] + [h["victim"] for h in hits])
    ctx.tokens.ensure({h["token"] for h in hits})
    for h in hits:
        if ctx.tokens.is_spoof(h["token"]) or not wscan.priced_ok(ctx, h["legs_out"]):
            continue
        for r in h["recipients"]:
            if not wscan.is_eoa(ctx, r) or ctx.is_allowed(r):
                continue
            legs = [x for x in h["legs_out"] if x["to"] == r]
            det = dict(victim=h["victim"], router=h["router"], router_name=TRUSTED_ROUTERS[h["router"]], token=h["token"],
                       amount=fmt_amount(sum(x["value"] for x in legs), ctx.tokens.get(h["token"])[1]))
            _emit(ctx, "router_sweep", r, h["tx"], h["block"], det, legs, victim=h["victim"])
            ctx.stats["g4_router_sweep"] += 1


# ---------- G5 NFT ----------
def nft_bulk(ctx, nft):
    hits = grules.nft_bulk(nft, ctx.txs, NFT_TRANSFER_HELPERS)
    if not hits:
        return
    ctx.ensure_codes([r for r, _ in hits])
    for (r, victim), legs in hits.items():
        if not wscan.is_eoa(ctx, r) or ctx.is_allowed(r):
            continue
        ctx.emit("nft_bulk", r, legs[0]["tx"], legs[0]["block"], dict(
            victim=victim, n_nfts=len(legs), nfts=[dict(token=x["token"], ident=str(x["ident"])) for x in legs[:10]]))
        ctx.stats["g5_nft_bulk"] += 1


def seaport_fee(ctx, evs):
    wrapped = set(WRAPPED_NATIVE.get(ctx.chain, {}))
    hits = [(e, d) for e in evs for d in [grules.seaport_fee_drain(e, wrapped)] if d and not ctx.is_allowed(d["fulfiller"])]
    if not hits:
        return
    ctx.ensure_codes([d["victim"] for _, d in hits])
    for e, d in hits:
        if wscan.is_eoa(ctx, d["victim"]):
            ctx.emit("seaport_fee_drain", d["fulfiller"], e["tx"], e["block"], dict(d, seaport=e["contract"]))
            ctx.stats["g5_seaport_fee"] += 1


# ---------- G6 address poisoning ----------
def poison_ext(ctx, tr, ap, txmeta):
    cp = wscan._state(ctx)["cp"]        # recent real stablecoin counterparties (maintained by W10)
    stables = STABLES.get(ctx.chain, set())
    ctx.tokens.ensure({t["token"] for t in tr})
    spoof = {t["token"] for t in tr if ctx.tokens.is_spoof(t["token"])}
    by_subject = defaultdict(lambda: dict(tiny=[], fake=[], txs=set()))
    for t in tr:
        tx = ctx.txs.get(t["tx"])
        if not tx or not tx.get("to"):
            continue
        if t["token"] in stables and t["value"] > 0:
            usd = ctx.prices.usd(ctx.chain, t["token"], t["value"], ctx.tokens.get(t["token"])[1])
            if usd is None or usd >= POISON_TINY_MAX_USD:
                continue
            look = grules.lookalike_of(t["frm"], list(cp.get(t["to"], {})))   # L -> V, L imitates V's partner
            if look:
                s = tx["from"] if tx["from"] == t["frm"] else tx["to"]
                by_subject[s]["tiny"].append((t, t["to"], t["frm"], look))
        elif t["token"] in spoof and t["frm"] != ZERO:
            look = grules.lookalike_of(t["to"], list(cp.get(t["frm"], {})))   # fake token "from" V to L
            if look:
                s = tx["to"] if tx["to"] != t["token"] else tx["from"]
                by_subject[s]["fake"].append((t, t["frm"], t["to"], look))
    sent = defaultdict(set)
    for h, m in ctx.txs.items():
        if m.get("block") is not None and txmeta.get(h):
            sent[m["from"]].add(h)
            if m.get("to"):
                sent[m["to"]].add(h)
    for s, d in by_subject.items():
        if ctx.is_allowed(s):
            continue
        attack = {x[0]["tx"] for x in d["tiny"] + d["fake"]}
        ratio = grules.attack_ratio(sent.get(s, set()), attack)
        if ratio < POISON_MIN_ATTACK_RATIO:
            continue
        for kind, items in (("poison_tiny", d["tiny"]), ("poison_counterfeit", d["fake"])):
            if not items:
                continue
            t0 = items[0][0]
            ctx.emit(kind, s, t0["tx"], t0["block"], dict(
                legs=len(items), n_victims=len({x[1] for x in items}), spoof=True, attack_ratio=round(ratio, 2),
                lookalikes=sorted({x[2] for x in items})[:10], txs=sorted(attack)[:10],
                sample=[dict(victim=x[1], lookalike=x[2], imitates=x[3], token=x[0]["token"]) for x in items[:3]]))
            ctx.stats["g6_" + kind] += 1
    # batched poison txs
    per_tx = defaultdict(list)
    for t in tr:
        per_tx[t["tx"]].append(t)
    n_ap = defaultdict(int)
    for a in ap:
        n_ap[a["tx"]] += 1
    for h, legs in per_tx.items():
        if len(legs) < POISON_BATCH_MIN_LEGS:
            continue
        m = txmeta.get(h) or {}
        res = grules.poison_batch(legs, len(legs) + n_ap[h], m.get("nlogs"), stables, spoof)
        if not res:
            continue
        looks = [x for x in legs if x["frm"] != ZERO and (grules.lookalike_of(x["to"], list(cp.get(x["frm"], {})))
                                                          or grules.lookalike_of(x["frm"], list(cp.get(x["to"], {}))))]
        s = m.get("to")
        if not looks or not s or ctx.is_allowed(s) or s in stables:
            continue
        ctx.emit("poison_batch", s, h, legs[0]["block"], dict(res, spoof=True, lookalike_legs=len(looks), txs=[h],
                                                               lookalikes=sorted({x["to"] for x in looks})[:10]))
        ctx.stats["g6_poison_batch"] += 1


# ---------- G7 lookalike contract creation ----------
def lookalike_contracts(ctx, tr, txmeta):
    created = {m["created"]: h for h, m in txmeta.items() if m.get("created") and m.get("status", 1) == 1}
    if not created:
        return
    cnt = defaultdict(int)
    for t in tr:
        cnt[t["token"]] += 1
    for m in txmeta.values():
        if m.get("to"):
            cnt[m["to"]] += 1
    busy = {a for a, n in cnt.items() if n >= LOOKALIKE_BUSY_MIN} | set(STABLES.get(ctx.chain, ())) | set(ALLOWLIST)
    for c, h in created.items():
        b = grules.lookalike_contract(c, busy)
        if b and not ctx.is_allowed(c):
            ctx.emit("lookalike_contract", c, h, txmeta[h]["block"], dict(imitates=b, deployer=txmeta[h]["from"]))
            ctx.stats["g7_lookalike_contract"] += 1


# ---------- G8 counterfactual destination ----------
def counterfactual(ctx, tr, ap, auth_txs):
    st = _state(ctx)
    cands = wrules.ghost_candidates(tr, ap, ctx.txs, auth_txs, ctx.is_allowed)
    if not cands:
        return
    got_in = {(t["tx"], t["to"]) for t in tr if t["value"] > 0}
    keep = {}
    for k, legs in cands.items():
        legs = [x for x in grules.counterfactual_keep(legs, tr) if (x["tx"], x["frm"]) not in got_in]
        if legs:                       # C received nothing at all in the tx (pools in swaps / vault routes do)
            keep[k] = legs
    if not keep:
        return
    ctx.tokens.ensure({x["token"] for legs in keep.values() for x in legs})
    priced = {}
    for k, legs in keep.items():
        legs = [x for x in legs if not ctx.tokens.is_spoof(x["token"]) and
                (ctx.prices.usd(ctx.chain, x["token"], x["value"], ctx.tokens.get(x["token"])[1]) or 0) >= MIN_USD]
        if legs:
            priced[k] = legs
    keep = dict(list(priced.items())[:200])
    ctx.stats["g8_truncated"] += max(0, len(priced) - 200)
    ctx.ensure_codes([c for _, c in keep])
    keep = {k: v for k, v in keep.items() if ctx.is_contract(k[1])}      # code exists today (W1c covers code-less)
    if not keep:
        return
    before = {}
    fn = getattr(ctx.rpc, "code_at", None)
    if fn is not None:                 # one batch: code at block - 1 (recent state only)
        try:
            before = fn([(c, legs[0]["block"] - 1) for (_, c), legs in keep.items()])
        except Exception:  # noqa: BLE001
            before = {}
    for (factory, c), legs in keep.items():
        b0 = before.get((c, legs[0]["block"] - 1))
        if b0 is not None:
            how = "archive" if b0 in ("0x", "") else None
        elif st["cf_lookups"] >= COUNTERFACTUAL_MAX_LOOKUPS:
            ctx.stats["g8_truncated"] += 1
            continue
        else:
            st["cf_lookups"] += 1
            how = wscan.created_in_tx(ctx, c, legs[0]["tx"], legs[0]["block"])
        if not how:
            continue
        info = ctx.analysis(c) or {}
        det = dict(child=c, created_check=how, caller=ctx.txs[legs[0]["tx"]]["from"], child_code_hash=info.get("code_hash"),
                   tokens=sorted({x["token"] for x in legs}), recipients=sorted({x["to"] for x in legs})[:5])
        _emit(ctx, "counterfactual_forward", factory, legs[0]["tx"], legs[0]["block"], det, legs, victim=c)
        ctx.stats["g8_counterfactual"] += 1


# ---------- G11 legit-delegator decoy batch ----------
def decoy_batch(ctx, tr):
    selfcalls = {t["tx"] for t in tr if (ctx.txs.get(t["tx"]) or {}).get("to") and
                 ctx.txs[t["tx"]]["to"] == ctx.txs[t["tx"]]["from"]}
    if not selfcalls:
        return
    ctx.ensure_codes([ctx.txs[h]["from"] for h in selfcalls])
    routers = set(TRUSTED_ROUTERS) | {a for a in ctx.allow}
    by_tx = defaultdict(list)
    for t in tr:
        if t["tx"] in selfcalls:
            by_tx[t["tx"]].append(t)
    for h, legs in by_tx.items():
        owner = ctx.txs[h]["from"]
        if not ctx.is_delegated(owner):
            continue
        delegate = "0x" + ctx.code_hex[owner][8:48].lower()
        if delegate not in LEGIT_7702_DELEGATES:
            continue                                     # W8b / D6 cover unknown delegates
        res = grules.decoy_batch(owner, legs, routers)
        if not res:
            continue
        rc = [r for r in res["recipients"] if not ctx.is_allowed(r)]
        ctx.ensure_codes(rc)
        rc = [r for r in rc if wscan.is_eoa(ctx, r)]
        need = [r for r in rc if r not in ctx.nonce]
        if need:
            ctx.nonce.update(ctx.rpc.nonces(need))
        ctx.tokens.ensure({x["token"] for x in res["legs"]})
        for r in rc:
            if ctx.nonce.get(r) != 0:                    # "never seen": the recipient has never sent a tx
                continue
            lg = [x for x in res["legs"] if x["to"] == r and not ctx.tokens.is_spoof(x["token"])]
            if not lg or not wscan.priced_ok(ctx, lg):
                continue
            _emit(ctx, "batch7702_decoy", r, h, lg[0]["block"], dict(victim=owner, delegate=delegate,
                                                                    legit_delegate=LEGIT_7702_DELEGATES[delegate],
                                                                    tokens=sorted({x["token"] for x in lg})), lg, victim=owner)
            ctx.stats["g11_decoy_batch"] += 1


# ---------- G12 full-balance pulls ----------
def full_balance(ctx, tr):
    """PTXPhish prerequisite: a third party's pull that leaves the victim with a zero balance of the token right after
    the tx (balanceOf at that block; recent state only, unknown otherwise). Marks pull evidence of this chunk."""
    st = _state(ctx)
    pend = [e for e in ctx.pev if e["type"] in PULL_EVIDENCE]
    if not pend or st["fb_lookups"] >= FULL_BALANCE_MAX_LOOKUPS:
        return
    calls = []
    for e in pend:
        d = e["detail"]
        victims = d.get("victims") or ([d["victim"]] if d.get("victim") else [])
        tok = d.get("token")
        if tok and victims:
            calls.append((e, victims[0], tok))
    calls = calls[:FULL_BALANCE_MAX_LOOKUPS - st["fb_lookups"]]
    if not calls:
        return
    st["fb_lookups"] += len(calls)
    try:
        res = ctx.rpc.batch([("eth_call", [{"to": tok, "data": "0x70a08231" + "0" * 24 + v[2:]}, hex(e["block"])])
                             for e, v, tok in calls], chunk=50, strict=False)
    except Exception:  # noqa: BLE001 - historical state may be unavailable
        return
    for (e, v, tok), r in zip(calls, res):
        if r in ("0x" + "0" * 64, "0x0"):
            e["detail"]["full_balance"] = True
            ctx.emit("full_balance_pull", e["address"], e["tx"], e["block"], dict(victim=v, token=tok, via=e["type"]))
            ctx.stats["g12_full_balance"] += 1


# ---------- G13 zero-nonce spender at approval time ----------
def zero_nonce_approvals(ctx, ap):
    st = _state(ctx)
    cands = [a for a in ap if a["value"] > 0 and a["spender"] not in (ZERO, a["owner"]) and not ctx.is_allowed(a["spender"])
             and not ctx.is_allowed(a["owner"])]
    if not cands or st["zn_lookups"] >= ZERO_NONCE_MAX_LOOKUPS or st.get("zn_codes", 0) >= 4 * ZERO_NONCE_MAX_LOOKUPS:
        return
    sp = list(dict.fromkeys(a["spender"] for a in cands))
    new = [x for x in sp if x not in ctx.code_hex][:4 * ZERO_NONCE_MAX_LOOKUPS - st.get("zn_codes", 0)]
    st["zn_codes"] = st.get("zn_codes", 0) + len(new)
    ctx.ensure_codes(new)
    eoas = [s for s in sp if wscan.is_eoa(ctx, s) and not ctx.is_delegated(s) and s not in ctx.nonce]
    eoas = eoas[:ZERO_NONCE_MAX_LOOKUPS - st["zn_lookups"]]
    if not eoas:
        return
    st["zn_lookups"] += len(eoas)
    nonce = ctx.rpc.nonces(eoas)        # 0 today => 0 at approval time (nonces only grow)
    ctx.nonce.update(nonce)
    later = [s for s in eoas if nonce.get(s)]
    fn = getattr(ctx.rpc, "nonces_at", None)
    if later and fn is not None:        # non-zero today: the nonce at the approval block (recent state only)
        pairs = {s: min(a["block"] for a in cands if a["spender"] == s) for s in later}
        try:
            got = fn([(s, b) for s, b in pairs.items()])
            nonce.update({s: got.get((s, b)) for s, b in pairs.items() if got.get((s, b)) is not None})
        except Exception:  # noqa: BLE001 - archive state refused: unknown, keep today's nonce
            ctx.stats["g13_state_unavailable"] += 1
    ctx.ensure_codes(list(dict.fromkeys(a["owner"] for a in cands if nonce.get(a["spender"]) == 0)))
    for a in cands:
        s = a["spender"]
        if nonce.get(s) != 0 or not wscan.is_eoa(ctx, a["owner"]):
            continue
        ctx.emit("zero_nonce_spender", s, a["tx"], a["block"], dict(victim=a["owner"], token=a["token"],
                                                                     kind=a.get("kind", "approval")))
        ctx.stats["g13_zero_nonce"] += 1


# ---------- ETH full-block pass ----------
def g_block(ctx, g1rows, senders, natives, phish_calls, incr, delegates, created, txmeta):
    for fn, args in ((fake_calls, (g1rows, senders, txmeta)), (many_funders, (natives,)),
                     (phish_deploy, (created,)), (phish_multicall, (phish_calls,)), (increase_allowance, (incr, txmeta)),
                     (forwarders, (delegates,))):
        _safe(ctx, fn, *args)


def fake_calls(ctx, rows, senders, txmeta):
    """G1: rows (h, to, sel, value, frm, block, nonce). EOA recipients -> `fake_call`; contract recipients with a
    non-bait selector, zero logs and >= 95 % of the value forwarded -> `fake_call_contract` (W3 forwarding check)."""
    if not rows:
        return
    ok = {h: (txmeta.get(h) or {}).get("status", 1) == 1 for h, *_ in rows}
    rows = [r for r in rows if ok.get(r[0], True) and not ctx.is_allowed(r[1]) and not ctx.is_allowed(r[4])
            and (r[2] in FAKE_CALL_SELECTORS or (txmeta.get(r[0]) or {}).get("nlogs") == 0)]
    ctx.ensure_codes([r[1] for r in rows])
    near = {frm for h, to, sel, v, frm, bn, n in rows
            if any(b != bn and abs(b - bn) <= FAKE_CALL_NEAR_BLOCKS for b in senders.get(frm, ())) or
            senders.get(frm, []).count(bn) > 1}
    eoa = [(h, to, grules.fake_call_name("0x" + sel, v), v, frm, bn) for h, to, sel, v, frm, bn, n in rows
           if wscan.is_eoa(ctx, to) and not ctx.is_delegated(to) and grules.fake_call_name("0x" + sel, v)
           and n <= FAKE_CALL_MAX_SENDER_NONCE]
    eoa = grules.fake_call_keep(eoa, near)
    if eoa:
        need = [r[1] for r in eoa if r[1] not in ctx.nonce]
        if need:
            ctx.nonce.update(ctx.rpc.nonces(need))
    price = ctx.prices.native.get(CHAINS[ctx.chain]["native"])
    for h, to, name, v, frm, bn in eoa:
        if (ctx.nonce.get(to) or 0) >= FAKE_CALL_MAX_RECIPIENT_NONCE:
            continue
        if price and v / 1e18 * price < MIN_USD:
            continue
        ctx.emit("fake_call", to, h, bn, dict(victim=frm, name=name, value_wei=str(v)))
        ctx.pdr.append(dict(tx=h, li=-4, block=bn, victim=frm, drainer=to, token=ZERO, symbol=CHAINS[ctx.chain]["native"],
                            decimals=18, amount=fmt_amount(v, 18), usd=round(v / 1e18 * price, 2) if price else None,
                            recipient=to))
        ctx.stats["g1_fake_call"] += 1
    # contract variant: zero logs (receipts source only), non-bait selector (W3 covers the bait names)
    cc = [(h, to, sel, v, frm, bn, "0x" + sel, dict(nonce=n)) for h, to, sel, v, frm, bn, n in rows
          if ctx.is_contract(to) and sel not in BAIT_CAPTURE and (txmeta.get(h) or {}).get("nlogs") == 0
          and frm not in near][:FAKE_CALL_CONTRACT_MAX]
    if cc:
        wscan.bait_forward(ctx, cc, ev_type="fake_call_contract")


def many_funders(ctx, natives):
    """G2: natives = [(frm, to, h, block, value, nonce)] plain native transfers of this chunk. Recipients with >= 3
    distinct funders in the chunk (or already tracked) are kept in table g_funds for FUNDERS_WINDOW_SEC."""
    conn = ctx.conn
    ensure_tables(conn)
    by_to = defaultdict(set)
    for frm, to, h, bn, v, n in natives:
        by_to[to].add(frm)
    tracked = {r[0] for r in conn.execute("SELECT DISTINCT recipient FROM g_funds WHERE chain=?", (ctx.chain,))}
    keep = {to for to, fs in by_to.items() if (len(fs) >= FUNDERS_TRACK_MIN or to in tracked) and not ctx.is_allowed(to)}
    if not keep:
        return
    ts = ctx.ts_of(sorted({bn for frm, to, h, bn, v, n in natives if to in keep}))
    now = now_ts()
    conn.executemany("INSERT OR IGNORE INTO g_funds(chain,recipient,funder,value,nonce,tx,block,ts) VALUES(?,?,?,?,?,?,?,?)",
                     [(ctx.chain, to, frm, str(v), n, h, bn, ts.get(bn) or now)
                      for frm, to, h, bn, v, n in natives if to in keep and not ctx.is_allowed(frm)])
    conn.execute("DELETE FROM g_funds WHERE chain=? AND ts < ?", (ctx.chain, now - FUNDERS_WINDOW_SEC))
    for to in keep:
        rows = [(r["funder"], int(r["value"]), r["nonce"], r["tx"], r["block"]) for r in conn.execute(
            "SELECT funder,value,nonce,tx,block FROM g_funds WHERE chain=? AND recipient=?", (ctx.chain, to))]
        hit = grules.funders_hit(rows)
        if not hit:
            continue
        ctx.ensure_codes([to])
        if not wscan.is_eoa(ctx, to):
            continue
        if to not in ctx.nonce:
            ctx.nonce.update(ctx.rpc.nonces([to]))
        if (ctx.nonce.get(to) or 0) > FUNDERS_MAX_RECIPIENT_NONCE:
            continue
        ctx.emit("many_funders", to, hit["tx"], hit["block"], dict(victims=hit["funders"][:50], n_funders=hit["n"],
                                                                  median_wei=hit["median_wei"]))
        ctx.stats["g2_many_funders"] += 1


def phish_deploy(ctx, created):
    """G3 (NIP-8): created = [(addr, tx, deployer, block)] top-level creations. Fingerprint + storage chain: slot 0 ->
    address A, A's slot 0 -> address B whose code has withdraw() / withdraw(uint256,address)."""
    hits = [(c, h, d, b, mc) for c, h, d, b in created for mc in [grules.phish_traits(ctx.code_hex.get(c))] if mc]
    if not hits:
        return
    fn = getattr(ctx.rpc, "storage_many", None)
    if fn is None:
        return
    s0 = fn([(c, 0) for c, *_ in hits])
    a_of = {c: "0x" + f"{v & ((1 << 160) - 1):040x}" for (c, _), v in s0.items() if v}
    s1 = fn([(a, 0) for a in set(a_of.values())]) if a_of else {}
    b_of = {a: "0x" + f"{v & ((1 << 160) - 1):040x}" for (a, _), v in s1.items() if v}
    ctx.ensure_codes(list(b_of.values()))
    for c, h, d, b, mc in hits:
        a = a_of.get(c)
        bb = b_of.get(a) if a else None
        if not bb or not ctx.is_contract(bb):
            continue
        sels = set((ctx.analysis(bb) or {}).get("selectors") or [])
        if not sels & PHISH_WITHDRAW_SELECTORS:
            continue
        ctx.emit("phish_deploy", c, h, b, dict(deployer=d, multicall=mc, slot0=a, withdraw_contract=bb))
        ctx.stats["g3_phish_deploy"] += 1


def phish_multicall(ctx, calls):
    """G3 (NIP-9): calls = [(h, to, frm, block, inp)] multicall txs; `to` has the phishing fingerprint, the calldata
    packs pull selectors and tokens of third-party EOAs moved in the tx."""
    if not calls:
        return
    ctx.ensure_codes([c[1] for c in calls])
    trs = defaultdict(list)
    for t in ctx.chunk_tr:
        trs[t["tx"]].append(t)
    for h, to, frm, bn, inp in calls:
        if ctx.is_allowed(to) or not grules.phish_traits(ctx.code_hex.get(to)):
            continue
        inner = grules.inner_selectors(inp)
        legs = [t for t in trs.get(h, []) if t["value"] > 0 and t["frm"] not in (frm, to, ZERO)]
        if not inner or not legs:
            continue
        ctx.ensure_codes([t["frm"] for t in legs])
        ctx.tokens.ensure({t["token"] for t in legs})
        legs = [t for t in legs if wscan.is_eoa(ctx, t["frm"]) and not ctx.tokens.is_spoof(t["token"])]
        if not legs or not wscan.priced_ok(ctx, legs):
            continue
        _emit(ctx, "phish_multicall", to, h, bn, dict(victims=sorted({t["frm"] for t in legs}), caller=frm,
                                                      inner=sorted(inner), recipients=sorted({t["to"] for t in legs})[:5]),
              legs, role=("collector", sorted({t["to"] for t in legs if t["to"] != to})[:3]))
        ctx.stats["g3_phish_multicall"] += 1


def increase_allowance(ctx, incr, txmeta):
    """G12: increaseAllowance(spender, x) signed by the owner where the spender is an EOA (dapps use contracts)."""
    if not incr:
        return
    incr = [x for x in incr if (txmeta.get(x["tx"]) or {}).get("status", 1) == 1 and not ctx.is_allowed(x["spender"])
            and x["spender"] not in (x["frm"], ZERO)]
    ctx.ensure_codes([x["spender"] for x in incr])
    for x in incr:
        if wscan.is_eoa(ctx, x["spender"]) and not ctx.is_delegated(x["spender"]):
            ctx.emit("increase_allowance_eoa", x["spender"], x["tx"], x["block"], dict(victim=x["frm"], token=x["token"],
                                                                                        amount=str(x["amount"])))
            ctx.stats["g12_increase_allowance"] += 1


def forwarders(ctx, delegates):
    """G11: EIP-7702 delegates whose code is the 'Forwarder' sweeper (initialize(address) + destination())."""
    todo = [(d, v) for d, v in delegates.items() if d not in LEGIT_7702_DELEGATES and not ctx.is_allowed(d)]
    todo = sorted(todo, key=lambda kv: -kv[1]["n"])[:40]
    ctx.ensure_codes([d for d, _ in todo])
    for d, v in todo:
        if bytecode.is_forwarder_7702(ctx.code_hex.get(d)):
            ctx.emit("forwarder_7702", d, v["tx"], v["block"], dict(authorizations=v["n"], victims=v["delegators"]))
            ctx.stats["g11_forwarder"] += 1


def ensure_tables(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS g_funds(chain TEXT, recipient TEXT, funder TEXT, value TEXT, nonce INTEGER, "
                 "tx TEXT, block INTEGER, ts INTEGER, UNIQUE(chain, tx))")
    conn.execute("CREATE INDEX IF NOT EXISTS g_funds_r ON g_funds(chain, recipient)")

