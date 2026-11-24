"""Detectors D1-D4 (pure functions over parsed logs) and tier/score assignment.

Parsed transfer: dict(tx, li, block, token, frm, to, value); approval: dict(tx, li, block, token, owner, spender, value, kind).
Evidence rows are dicts: type, address, tx, block, detail."""
from collections import defaultdict

from .constants import (APPROVE_SELECTORS, BAIT_ADDR_SELECTORS, BATCH_APPROVAL_MIN, D2_MAX_SHARE, D2_MIN_SHARE, D3_MIN_VICTIMS, D3_WINDOW,
                        D4_MIN_TXS, D7_T1_VICTIMS, D8_MAX_SPENDER_NONCE, D8_MIN_VICTIM_NONCE, D10_KIT_DEADLINE,
                        D10_KIT_TOLERANCE, KIT_APPROVAL_AMOUNTS, MS_DEADLINE_MAX, MS_DEADLINE_MIN, MS_NEW_MAX_PERCENT,
                        MS_NEW_SELECTORS, OWNER_COLLECTOR_T1_VICTIMS, PERMIT2, SCORE, SEL_MULTICALL_DEADLINE,
                        SEL_P2_TRANSFER_FROM, SEL_P2_TRANSFER_FROM_BATCH, SEL_PERMIT2_BATCH, SEL_PERMIT2_SINGLE,
                        SEL_PERMIT_2612, SEL_PERMIT_DAI, SEL_R02_EXACT_INPUT_SINGLE, SEL_TRANSFER_FROM,
                        SEL_V3_EXACT_INPUT_SINGLE, SWAP_R02_SELECTORS, SWAP_V2_ETH_IN_SELECTORS, SWAP_V2_SELECTORS, UINT256_MAX, V3_KIT_DEADLINE,
                        V3_KIT_FEE, V3_KIT_TOLERANCE, XSPLIT_MAX_GAP, XSPLIT_MAX_SHARE, XSPLIT_MIN_SHARE, ZERO)


# ---------- D1 seed_activity ----------
def d1_seed_activity(chain, transfers, approvals, seeds):
    """Approval/ApprovalForAll with spender in seeds, Transfer to a seed. Returns (evidence, drain_legs)."""
    ev, legs = [], []
    for a in approvals:
        if not seeds.has(chain, a["spender"]):
            continue
        if a["value"] == 0:   # revoke (ERC-20 amount 0 / ApprovalForAll false)
            continue
        ev.append(dict(type="seed_activity", address=a["spender"], tx=a["tx"], block=a["block"],
                       detail=dict(victim=a["owner"], kind="approval_all" if a["kind"] == "all" else "approval",
                                   token=a["token"])))
    for t in transfers:
        if t["to"] != ZERO and seeds.has(chain, t["to"]):
            ev.append(dict(type="seed_activity", address=t["to"], tx=t["tx"], block=t["block"],
                           detail=dict(victim=t["frm"], kind="transfer", token=t["token"])))
            legs.append(t)
    return ev, legs


# ---------- redemption guard (D2 / R-A1) ----------
D2_MIN_RECIPIENTS, D2_MAX_RECIPIENTS = 2, 3     # drainer splits: operator + affiliate, sometimes +1
REDEEM_MIN_RECIPIENTS = 4


def mint_burn_by_tx(transfers):
    """tx -> list of mint/burn transfers (Transfer from or to the zero address, value > 0)."""
    out = defaultdict(list)
    for t in transfers:
        if (t["frm"] == ZERO) != (t["to"] == ZERO) and t["value"] > 0:
            out[t["tx"]].append(t)
    return out


def redemption_like(mintburn, tx_to, recipients):
    """A vault/share-token redemption or deposit batch is not a drainer split. True if the same tx
    * mints/burns a token whose contract is tx.to, or burns tokens held by tx.to (the contract burns its own shares), or
    * pays >= 4 distinct recipients with at least one burn per recipient (one redemption per payee).
    mintburn: mint/burn transfers of that tx; tx_to: lower-case tx.to; recipients: distinct pull-leg recipients."""
    if not mintburn:
        return False
    burns = [m for m in mintburn if m["to"] == ZERO]
    if any(m["token"] == tx_to for m in mintburn) or any(m["frm"] == tx_to for m in burns):
        return True
    return len(set(recipients)) >= REDEEM_MIN_RECIPIENTS and len(burns) >= len(set(recipients))


# ---------- D2 split_pull ----------
def d2_candidates(transfers, is_allowed):
    """Same tx, same token, same `from` (victim), >=2 distinct recipients, largest recipient share in [0.60, 0.95]."""
    groups = defaultdict(list)
    for t in transfers:
        if t["frm"] != ZERO and t["value"] > 0:
            groups[(t["tx"], t["token"], t["frm"])].append(t)
    out = []
    for (tx, token, victim), legs in groups.items():
        if len(legs) < 2 or is_allowed(victim):
            continue
        per = defaultdict(int)
        for t in legs:
            per[t["to"]] += t["value"]
        if len(per) < 2:
            continue
        total = sum(per.values())
        top = max(per.values()) / total
        if D2_MIN_SHARE <= top <= D2_MAX_SHARE:
            out.append(dict(tx=tx, token=token, victim=victim, legs=legs, block=legs[0]["block"],
                            per={w: v / total for w, v in per.items()}))
    return out


def d2_confirm(cand, tx, is_contract, is_allowed, is_legit=lambda a: False, mintburn=()):
    """tx = {'from','to'} of the transaction. Requires tx.from != victim, tx.to a non-allowlisted contract, victim an
    EOA (or 7702-delegated EOA: is_contract() must return False for those), 2-3 recipients, and no vault-redemption
    shape (mint/burn in the same tx, see redemption_like). mintburn: mint/burn transfers of this tx. Returns dict or None."""
    to, frm = (tx.get("to") or "").lower(), (tx.get("from") or "").lower()
    victim = cand["victim"]
    if not D2_MIN_RECIPIENTS <= len(cand["per"]) <= D2_MAX_RECIPIENTS:
        return None
    if redemption_like(mintburn, to, cand["per"]):
        return None
    if not to or frm == victim or to == victim or to == cand["token"] or is_allowed(to):
        return None
    if not is_contract(to) or is_contract(victim):
        return None
    # a router/aggregator paying itself (or the tx sender) is not a drainer split; labelled legit recipients neither
    if any(w in (to, frm) or is_legit(w) for w in cand["per"]):
        return None
    ranked = sorted(cand["per"].items(), key=lambda kv: -kv[1])
    recipients = [dict(wallet=w, share=round(s, 4), role="affiliate" if i == 0 else "operator")
                  for i, (w, s) in enumerate(ranked)]
    return dict(drainer=to, victim=victim, recipients=recipients, tx_from=frm)


# ---------- D3 multi_victim_pull ----------
def d3_candidates(transfers, owner_spenders, payout_wallets, exclude):
    """Candidates by tx: transfers whose `from` has a recent approval on record, or whose recipient is a known
    payout/seed wallet. exclude: set of (tx, from) already explained by D2."""
    by_tx = defaultdict(list)
    for t in transfers:
        if t["frm"] == ZERO or t["value"] == 0 or (t["tx"], t["frm"]) in exclude:
            continue
        if t["frm"] in owner_spenders or t["to"] in payout_wallets:
            by_tx[t["tx"]].append(t)
    return by_tx


def d3_confirm(legs, tx, owner_spenders, payout_wallets, is_contract, is_allowed):
    """Victims = distinct leg.from != tx.from for which tx.to was approved, or whose recipient is a payout wallet."""
    to, frm = (tx.get("to") or "").lower(), (tx.get("from") or "").lower()
    if not to or is_allowed(to) or not is_contract(to):
        return None
    victims, kept = set(), []
    for t in legs:
        v = t["frm"]
        if v == frm or v == to or t["token"] == to:
            continue
        if to in owner_spenders.get(v, ()) or t["to"] in payout_wallets:
            if not is_contract(v):
                victims.add(v)
                kept.append(t)
    if not victims:
        return None
    return dict(drainer=to, victims=sorted(victims), legs=kept)


# ---------- D4 pays_known_operator ----------
def d4_candidates(transfers, payout_wallets, is_allowed):
    out = []
    for t in transfers:
        if t["to"] in payout_wallets and t["frm"] != t["to"] and t["frm"] != ZERO and not is_allowed(t["frm"]) \
                and t["value"] > 0:
            out.append(t)
    return out


# ---------- D8 eoa_spender_pull ----------
def d8_candidates(transfers, txs, is_allowed):
    """Needs from/to of every tx (receipts source). A pull executed by an EOA directly on the token (transferFrom) or on
    Permit2 (signature transfer): Transfer.from (victim) != tx.from, recipient != tx.from, neither spender nor recipient
    carries a legitimate label. This is the dominant ETH drain shape in the 2025-26 incident set (victim approved /
    signed for an EOA, the operator pulls later)."""
    out = []
    for t in transfers:
        tx = txs.get(t["tx"])
        if not tx or t["value"] == 0 or t["frm"] == ZERO or t["to"] == ZERO:
            continue
        spender, to = tx["from"], tx.get("to")
        if not to or t["frm"] in (spender, to):
            continue
        if to == t["token"]:
            via = "transferFrom"
        elif to == PERMIT2:
            via = "permit2"
        elif is_allowed(to):
            continue
        else:   # tx.to may be the operator's own EIP-7702-delegated EOA batching the pulls; d8_confirm checks its code
            via, spender = "7702", to
        if t["to"] in (spender, t["frm"]) or is_allowed(spender) or is_allowed(t["to"]) or is_allowed(t["frm"]):
            continue
        out.append(dict(t, spender=spender, via=via))
    return out


def d8_confirm(c, is_contract, nonce, is_delegated=lambda a: False):
    """Victim and recipient are EOAs (7702-delegated EOAs count as EOAs), victim nonce >= D8_MIN_VICTIM_NONCE (not a
    custodial deposit address), spender nonce < D8_MAX_SPENDER_NONCE (not a high-volume sweeper). nonce: addr -> int|None."""
    if is_contract(c["frm"]) or is_contract(c["to"]) or is_contract(c["spender"]):
        return False
    if c.get("via") == "7702" and not is_delegated(c["spender"]):
        return False          # tx.to is a plain EOA (no code: nothing executed) or unknown
    nv, ns = nonce.get(c["frm"]), nonce.get(c["spender"])
    if nv is None or ns is None:
        return False
    return nv >= D8_MIN_VICTIM_NONCE and ns < D8_MAX_SPENDER_NONCE


# ---------- calldata helpers ----------
def _words(data: bytes, start=0):
    return lambda i: int.from_bytes(data[start + 32 * i: start + 32 * i + 32], "big")


def _addr(v: int) -> str:
    return "0x" + f"{v & ((1 << 160) - 1):040x}"


def _hexbytes(inp):
    s = inp or "0x"
    s = s[2:] if s.startswith("0x") else s
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


# ---------- D7 bait(address) ----------
def decode_bait(inp):
    """Calldata of a bait(address) call -> (selector, name, address argument) or None (MS Drainer kit notes S1).
    The argument is the kit customer's payout wallet: balance[arg] += msg.value."""
    b = _hexbytes(inp)
    if len(b) < 36:
        return None
    sel = b[:4].hex()
    if sel not in BAIT_ADDR_SELECTORS:
        return None
    w = int.from_bytes(b[4:36], "big")
    if w >> 160:                 # not an ABI-encoded address
        return None
    return sel, BAIT_ADDR_SELECTORS[sel], _addr(w)


def bait_tier(victims):
    return "T1" if victims >= D7_T1_VICTIMS else "T2"


# ---------- D9 approval_fingerprint ----------
def d9_candidates(approvals, is_allowed):
    """ERC-20 Approval whose amount equals a kit-hard-coded value (KIT_APPROVAL_AMOUNTS, a fingerprint): spender = kit
    spender (operator EOA or drainer contract), owner = victim."""
    out = []
    for a in approvals:
        kit = KIT_APPROVAL_AMOUNTS.get(a["value"]) if a["kind"] == "approval" else None
        if not kit or a["spender"] in (ZERO, a["owner"]) or is_allowed(a["spender"]):
            continue
        out.append(dict(a, kit=kit))
    return out


# ---------- D10 foreign_recipient_swap ----------
def _decode_path_swap(b: bytes, with_deadline: bool):
    """ABI body (after the selector) of swapExact...(amountIn, amountOutMin, address[] path, address to[, deadline])."""
    if len(b) < 32 * (5 if with_deadline else 4):
        return None
    w = _words(b)
    off = w(2)
    if off + 32 > len(b):
        return None
    n = int.from_bytes(b[off:off + 32], "big")
    if n < 2 or n > 8 or off + 32 + 32 * n > len(b):
        return None
    path = [_addr(int.from_bytes(b[off + 32 + 32 * i: off + 64 + 32 * i], "big")) for i in range(n)]
    return dict(amount_in=w(0), amount_out_min=w(1), path=path, to=_addr(w(3)),
                deadline=w(4) if with_deadline else None)


def _eth_in(b: bytes, value: int):
    """ABI body of swapExactETHForTokens[SupportingFeeOnTransferTokens](amountOutMin, address[] path, to, deadline);
    amountIn = tx.value."""
    if len(b) < 32 * 4:
        return None
    w = _words(b)
    off = w(1)
    if off + 32 > len(b):
        return None
    n = int.from_bytes(b[off:off + 32], "big")
    if n < 2 or n > 8 or off + 32 + 32 * n > len(b):
        return None
    path = [_addr(int.from_bytes(b[off + 32 + 32 * i: off + 64 + 32 * i], "big")) for i in range(n)]
    if w(2) >> 160:
        return None
    return dict(amount_in=value, amount_out_min=w(0), path=path, to=_addr(w(2)), deadline=w(3))


def decode_swaps(inp, value=0):
    """V2-router swapExactTokensFor{ETH,Tokens}[SupportingFeeOnTransferTokens], swapExactETHForTokens[...] (N6:
    amountIn = tx.value) and SwapRouter02 multicall(uint256 deadline, bytes[]) with inner
    swapExactTokensForTokens(amountIn, amountOutMin, path, to).
    Returns [dict(fn, amount_in, amount_out_min, path, to, deadline)] (empty when not a recognised swap)."""
    b = _hexbytes(inp)
    if len(b) < 4:
        return []
    sel, body = b[:4].hex(), b[4:]
    out = []
    try:
        if sel in SWAP_V2_SELECTORS:
            d = _decode_path_swap(body, True)
            if d:
                out.append(dict(d, fn=SWAP_V2_SELECTORS[sel]))
        elif sel in SWAP_V2_ETH_IN_SELECTORS:
            d = _eth_in(body, value or 0)
            if d:
                out.append(dict(d, fn=SWAP_V2_ETH_IN_SELECTORS[sel]))
        elif sel == SEL_MULTICALL_DEADLINE and len(body) >= 64:
            w = _words(body)
            deadline, off = w(0), w(1)
            n = int.from_bytes(body[off:off + 32], "big")
            base = off + 32
            for i in range(min(n, 16)):
                p = base + int.from_bytes(body[base + 32 * i: base + 32 * i + 32], "big")
                ln = int.from_bytes(body[p:p + 32], "big")
                inner = body[p + 32: p + 32 + ln]
                if len(inner) < 4:
                    continue
                isel = inner[:4].hex()
                if isel in SWAP_R02_SELECTORS:
                    d = _decode_path_swap(inner[4:], False)
                    if d:
                        out.append(dict(d, deadline=deadline, fn="multicall/" + SWAP_R02_SELECTORS[isel]))
                elif isel in SWAP_V2_SELECTORS:
                    d = _decode_path_swap(inner[4:], True)
                    if d:
                        out.append(dict(d, fn="multicall/" + SWAP_V2_SELECTORS[isel]))
    except (IndexError, ValueError):
        return []
    return out + decode_v3_singles(b)


def decode_v3_singles(b: bytes):
    """K8: every V3 `exactInputSingle` call found in the calldata, top-level or embedded at a 32-byte word boundary of a
    batch (EIP-5792 wallet_sendCalls executes through the victim's 7702 account, so the router call is nested).
    SwapRouter (with deadline) 0x414bf389 and SwapRouter02 (without) 0x04e45aaf; static tuple decoded in place."""
    out = []
    for sel, with_dl in ((SEL_V3_EXACT_INPUT_SINGLE, True), (SEL_R02_EXACT_INPUT_SINGLE, False)):
        sb = bytes.fromhex(sel)
        need = 32 * (8 if with_dl else 7)
        i = b.find(sb)
        while i != -1:
            body = b[i + 4: i + 4 + need]
            if len(body) == need and (i == 0 or (i - 4) % 32 == 0):
                w = _words(body)
                tin, tout, fee, rcpt = w(0), w(1), w(2), w(3)
                if not (tin >> 160 or tout >> 160 or rcpt >> 160 or fee >= 1 << 24):
                    k = 5 if with_dl else 4
                    out.append(dict(fn="exactInputSingle" + ("" if with_dl else "(R02)") + ("" if i == 0 else "/batch"),
                                    path=[_addr(tin), _addr(tout)], fee=fee, to=_addr(rcpt),
                                    deadline=w(4) if with_dl else None, amount_in=w(k), amount_out_min=w(k + 1)))
            i = b.find(sb, i + 1)
    return out


def d10_candidate(swap, tx_from, block_ts):
    """Flag shape: amountOutMin == 0 and the swap pays someone other than the signer (to != tx.from; router sentinels
    address(1)/address(2) excluded). Returns detail dict (kit = deadline ~ block.timestamp + 99 990 s) or None.
    K8 extension: a V3 exactInputSingle paying a foreign recipient is also a candidate with amountOutMinimum > 0 when it
    has the kit shape (fee 3000 and deadline = block time + 300 s +/- 60, `v3_kit_shape`); that shape alone is never a
    kit confirmation (the kit-amount approval in the same tx is, see k7k8_tx). The recipient must additionally be an EOA
    (checked by the caller with code)."""
    to = swap["to"]
    if swap["amount_in"] == 0 or to == tx_from or int(to, 16) <= 0xFFFF:
        return None
    delta = (swap["deadline"] - block_ts) if (swap.get("deadline") is not None and block_ts) else None
    v3_shape = swap.get("fee") == V3_KIT_FEE and delta is not None and abs(delta - V3_KIT_DEADLINE) <= V3_KIT_TOLERANCE
    if swap["amount_out_min"] != 0 and not v3_shape:
        return None
    kit = delta is not None and abs(delta - D10_KIT_DEADLINE) <= D10_KIT_TOLERANCE
    d = dict(victim=tx_from, recipient=to, token=swap["path"][0], token_out=swap["path"][-1],
             amount_in=str(swap["amount_in"]), fn=swap["fn"], deadline_delta=delta, kit=kit)
    if v3_shape:
        d["v3_kit_shape"] = True
    return d


# ---------- K1 MS_NEW bait ----------
def decode_ms_new(inp):
    """MS_NEW bait calldata: selector + (address depositer, address handler, address keeper, uint8 percent, bool) =
    4 + 5 x 32 B. Strict ABI checks (address words < 2^160, percent <= 99, bool in {0, 1}). Returns dict or None."""
    b = _hexbytes(inp)
    if len(b) < 4 + 160 or b[:4].hex() not in MS_NEW_SELECTORS:
        return None
    w = _words(b, 4)
    dep, han, kee, pct, cb = w(0), w(1), w(2), w(3), w(4)
    if dep >> 160 or han >> 160 or kee >> 160 or pct > MS_NEW_MAX_PERCENT or cb > 1:
        return None
    sel = b[:4].hex()
    return dict(selector=sel, name=MS_NEW_SELECTORS[sel], depositer=_addr(dep), handler=_addr(han), keeper=_addr(kee),
                percent=pct, cashback=bool(cb))


# ---------- N4 / N7 approve-family calldata ----------
def decode_approve(inp):
    """approve / increaseAllowance / increaseApproval(address spender, uint256 amount) calldata -> dict(fn, spender,
    amount) or None."""
    b = _hexbytes(inp)
    if len(b) < 4 + 64 or b[:4].hex() not in APPROVE_SELECTORS:
        return None
    w = _words(b, 4)
    if w(0) >> 160:
        return None
    return dict(fn=APPROVE_SELECTORS[b[:4].hex()], spender=_addr(w(0)), amount=w(1))


def kit_router_xtx(swap_ts, swap_tx, owner_events, max_sec):
    """N7: owner_events = [(ts, tx, spender, amount)] kit-amount allowance increases of the swap signer to legitimate
    routers. Returns the latest event in [swap_ts - max_sec, swap_ts] from ANOTHER tx, or None."""
    best = None
    for ev in owner_events or ():
        ts, tx = ev[0], ev[1]
        if tx != swap_tx and ts is not None and swap_ts is not None and 0 <= swap_ts - ts <= max_sec:
            if best is None or ts > best[0]:
                best = ev
    return best


# ---------- K4 millisecond deadlines ----------
def is_ms_deadline(v):
    return v is not None and MS_DEADLINE_MIN <= v <= MS_DEADLINE_MAX


def decode_permit(inp):
    """EIP-2612 permit(owner, spender, value, deadline, v, r, s); DAI permit(holder, spender, nonce, expiry, allowed,
    v, r, s); Permit2 permit(owner, PermitSingle{(token, amount, expiration, nonce), spender, sigDeadline}, sig) (static
    struct, encoded inline) and permit(owner, PermitBatch{PermitDetails[] details, spender, sigDeadline}, sig) (dynamic
    struct behind an offset). Returns dict(kind, owner, spender, tokens, deadlines{field: value}) or None; tokens = []
    for EIP-2612 / DAI (the token is tx.to)."""
    b = _hexbytes(inp)
    if len(b) < 4 + 32 * 3:
        return None
    sel, body = b[:4].hex(), b[4:]
    w = _words(body)
    try:
        if sel == SEL_PERMIT_2612 and len(body) >= 32 * 7:
            if w(0) >> 160 or w(1) >> 160:
                return None
            return dict(kind="permit", owner=_addr(w(0)), spender=_addr(w(1)), tokens=[], deadlines={"deadline": w(3)})
        if sel == SEL_PERMIT_DAI and len(body) >= 32 * 8:
            if w(0) >> 160 or w(1) >> 160 or w(4) > 1:
                return None
            return dict(kind="permit_dai", owner=_addr(w(0)), spender=_addr(w(1)), tokens=[], deadlines={"expiry": w(3)})
        if sel == SEL_PERMIT2_SINGLE and len(body) >= 32 * 8:
            if w(0) >> 160 or w(1) >> 160 or w(5) >> 160:
                return None
            return dict(kind="permit2_single", owner=_addr(w(0)), spender=_addr(w(5)), tokens=[_addr(w(1))],
                        deadlines={"expiration": w(3), "sigDeadline": w(6)})
        if sel == SEL_PERMIT2_BATCH:
            if w(0) >> 160:
                return None
            o = w(1)
            if o + 96 > len(body):
                return None
            sw = _words(body, o)
            doff, spender, sig_dl = sw(0), sw(1), sw(2)
            if spender >> 160 or o + doff + 32 > len(body):
                return None
            n = int.from_bytes(body[o + doff: o + doff + 32], "big")
            if n == 0 or n > 64 or o + doff + 32 + 128 * n > len(body):
                return None
            dw = _words(body, o + doff + 32)
            dl = {"sigDeadline": sig_dl}
            dl.update({f"expiration[{i}]": dw(4 * i + 2) for i in range(n)})
            return dict(kind="permit2_batch", owner=_addr(w(0)), spender=_addr(spender),
                        tokens=[_addr(dw(4 * i)) for i in range(n)], deadlines=dl)
    except (IndexError, ValueError, OverflowError):
        return None
    return None


def ms_deadline_fields(permit):
    """Fields of a decoded permit whose value lies in [1e12, 1e13] (milliseconds used as seconds)."""
    return sorted(k for k, v in (permit or {}).get("deadlines", {}).items() if is_ms_deadline(v))


# ---------- K5 / K12 one-shot EOA spenders ----------
def decode_pull_call(inp, to):
    """Top-level pull call: token.transferFrom(from, to, amount) (tx.to = token) or Permit2 transferFrom(from, to,
    amount, token) / transferFrom(AllowanceTransferDetails[]). Returns [(victim, recipient, token)]; token None = tx.to."""
    b = _hexbytes(inp)
    if len(b) < 4 + 64:
        return []
    sel, body = b[:4].hex(), b[4:]
    w = _words(body)
    try:
        if sel == SEL_TRANSFER_FROM and to != PERMIT2 and len(body) >= 96:
            if w(0) >> 160 or w(1) >> 160:
                return []
            return [(_addr(w(0)), _addr(w(1)), None)]
        if sel == SEL_P2_TRANSFER_FROM and to == PERMIT2 and len(body) >= 128:
            if w(0) >> 160 or w(1) >> 160 or w(3) >> 160:
                return []
            return [(_addr(w(0)), _addr(w(1)), _addr(w(3)))]
        if sel == SEL_P2_TRANSFER_FROM_BATCH and to == PERMIT2:
            o = w(0)
            n = int.from_bytes(body[o:o + 32], "big")
            if n == 0 or n > 64 or o + 32 + 128 * n > len(body):
                return []
            dw = _words(body, o + 32)
            return [(_addr(dw(4 * i)), _addr(dw(4 * i + 1)), _addr(dw(4 * i + 3))) for i in range(n)]
    except (IndexError, ValueError, OverflowError):
        return []
    return []


def oneshot_links(pulls, funds, returns, fund_window, return_window):
    """K5 / K12: link one-shot workers to hubs. pulls: worker -> [dict(tx, block, victim, token)] (already filtered:
    worker nonce <= 3, third-party victim, value really moved); funds: worker -> [(hub, tx, block)] plain native
    transfers TO the worker; returns: worker -> [(hub, tx, block)] plain native transfers FROM the worker with gas
    25 200. A pull is linked to a hub that funded the worker within `fund_window` blocks before it and/or received the
    leftover within `return_window` blocks after it. Returns [dict(hub, worker, pull, fund_tx, return_tx)]."""
    out = []
    for worker, pl in pulls.items():
        for p in pl:
            hubs = {}
            for hub, tx, blk in funds.get(worker, []):
                if hub not in (worker, p["victim"]) and p["block"] - fund_window <= blk <= p["block"]:
                    hubs.setdefault(hub, {})["fund_tx"] = tx
            for hub, tx, blk in returns.get(worker, []):
                if hub not in (worker, p["victim"]) and p["block"] <= blk <= p["block"] + return_window:
                    hubs.setdefault(hub, {})["return_tx"] = tx
            for hub, h in hubs.items():
                out.append(dict(hub=hub, worker=worker, pull=p, fund_tx=h.get("fund_tx"), return_tx=h.get("return_tx")))
    return out


# ---------- K7 / K8 batch approval drain ----------
def k7k8_tx(approvals, transfers, kit_amounts, is_legit):
    """One tx; approvals / transfers = parsed logs of that tx. For every owner O that approved in this tx:
      * K7 `batch_approval_drain`: >= 2 Approval logs of O with a kit amount or uint256 max;
      * K8 `kit_router_swap`: >= 1 Approval of O with a kit amount to a LEGITIMATE spender (router; is_legit);
    and in the same tx tokens left O (Transfer from O, value > 0), nothing came back to O, and a third address R (not
    O, not legit, not an approved spender, not a token contract of this tx) received tokens. Returns
    [dict(rule, owner, recipients{wallet: [legs]}, approvals, kit)]; the caller checks that R is an EOA."""
    out = []
    by_owner = defaultdict(list)
    for a in approvals:
        if a["kind"] == "approval" and a["value"] > 0:
            by_owner[a["owner"]].append(a)
    for owner, aps in by_owner.items():
        fp = [a for a in aps if a["value"] in kit_amounts or a["value"] == UINT256_MAX]
        kit_legit = [a for a in aps if a["value"] in kit_amounts and is_legit(a["spender"])]
        rules = (["batch_approval_drain"] if len(fp) >= BATCH_APPROVAL_MIN else []) + (["kit_router_swap"] if kit_legit else [])
        if not rules:
            continue
        if not any(t["frm"] == owner and t["value"] > 0 for t in transfers):
            continue
        if any(t["to"] == owner and t["value"] > 0 for t in transfers):
            continue                      # the owner got something back: an ordinary (self-paying) swap
        spenders = {a["spender"] for a in aps}
        tokens = {t["token"] for t in transfers}
        rec = defaultdict(list)
        for t in transfers:
            r = t["to"]
            if t["value"] == 0 or r in (owner, ZERO) or r in spenders or r in tokens or is_legit(r):
                continue
            rec[r].append(dict(token=t["token"], value=str(t["value"]), direct=t["frm"] == owner))
        if not rec:
            continue
        kit = sorted({kit_amounts[a["value"]] for a in aps if a["value"] in kit_amounts})
        for rule in rules:
            used = fp if rule == "batch_approval_drain" else kit_legit
            out.append(dict(rule=rule, owner=owner, recipients=dict(rec), kit=kit,
                            approvals=[dict(spender=a["spender"], token=a["token"],
                                            amount="max" if a["value"] == UINT256_MAX else str(a["value"])) for a in used]))
    return out


# ---------- R-A1 cross-tx split ----------
def xsplit_groups(transfers, txs, is_allowed, mintburn=None):
    """Pull legs keyed by (caller=tx.from, subject, victim, token) where victim = Transfer.from != tx.from. subject =
    tx.from when tx.to is the token itself / Permit2 (EOA spender), else tx.to (puller contract). Only keys seen in
    >= 2 different txs are returned (single-tx splits are D2's job). Needs tx.from/to of every tx (receipts source)."""
    groups = defaultdict(list)
    rec_by_tx = defaultdict(set)
    for t in transfers:
        if t["frm"] != ZERO and t["to"] != ZERO:
            rec_by_tx[t["tx"]].add(t["to"])
    for t in transfers:
        tx = txs.get(t["tx"])
        if not tx or t["value"] == 0 or t["frm"] == ZERO or t["to"] == ZERO:
            continue
        if mintburn and redemption_like(mintburn.get(t["tx"]), (tx.get("to") or "").lower(), rec_by_tx[t["tx"]]):
            continue
        caller, to = tx["from"], tx.get("to")
        if not to or t["frm"] in (caller, to) or t["to"] in (caller, t["frm"]):
            continue
        subject = caller if to in (t["token"], PERMIT2) else to
        if is_allowed(subject) or is_allowed(caller) or is_allowed(t["to"]) or is_allowed(t["frm"]):
            continue
        groups[(caller, subject, t["frm"], t["token"])].append(t)
    return {k: v for k, v in groups.items() if len({x["tx"] for x in v}) >= 2 and len({x["to"] for x in v}) >= 2}


def xsplit_confirm(legs, ts_of, max_gap=XSPLIT_MAX_GAP):
    """legs of one group; ts_of(block) -> unix ts. Finds a run of legs within `max_gap` seconds that spans >= 2 txs and
    >= 2 recipients with the largest recipient share in [0.60, 0.99]. Returns dict(legs, recipients, txs) or None."""
    legs = sorted(legs, key=lambda x: (x["block"], x["li"]))
    for i in range(len(legs)):
        t0 = ts_of(legs[i]["block"])
        if t0 is None:
            continue
        run = [x for x in legs[i:] if ts_of(x["block"]) is not None and ts_of(x["block"]) - t0 <= max_gap]
        if len({x["tx"] for x in run}) < 2:
            continue
        per = defaultdict(int)
        for x in run:
            per[x["to"]] += x["value"]
        if len(per) < 2:
            continue
        total = sum(per.values())
        top = max(per.values()) / total
        if XSPLIT_MIN_SHARE <= top <= XSPLIT_MAX_SHARE:
            ranked = sorted(per.items(), key=lambda kv: -kv[1])
            rec = [dict(wallet=w, share=round(v / total, 4), role="affiliate" if j == 0 else "operator")
                   for j, (w, v) in enumerate(ranked)]
            return dict(legs=run, recipients=rec, txs=sorted({x["tx"] for x in run}))
    return None


# ---------- sliding window helper (D3) ----------
def window_hit(events, window=D3_WINDOW, need=D3_MIN_VICTIMS):
    """events: [(ts, victim)] -> True if >= `need` distinct victims fall inside any `window` seconds span."""
    ev = sorted(e for e in events if e[0] is not None)
    lo = 0
    from collections import Counter
    cnt = Counter()
    for hi, (ts, v) in enumerate(ev):
        cnt[v] += 1
        while ts - ev[lo][0] > window:
            cnt[ev[lo][1]] -= 1
            if cnt[ev[lo][1]] == 0:
                del cnt[ev[lo][1]]
            lo += 1
        if len(cnt) >= need:
            return True
    return False


# ---------- tiers / score ----------
PULL_LABELS = {"eoa_spender_pull", "split_xtx", "split_pull", "multi_victim_pull", "owner_collect", "oneshot_hub",
               "prefund_hub", "kit_pull"}


def assign_tier(labels, victims, active):
    """labels: set of detector labels. Returns tier 'T1'|'T2'|'T3'|None.
    T1 confirmed: seed with observed activity; D2 with >=3 victims; D2 + family match to a seed.
    T2 strong: D2 with 1-2 victims; D4; family match + any activity; D8 with >=3 victims within 24 h.
    T3 suspect: D3 alone, D6, D7, D8 (1-2 victims), red-flag selectors, family match without activity.
    Kit rules (kit notes): approval_fingerprint (D9) = T1; bait_payable (D7 bait(address)) T1 with >= 3 victims else T2;
    split_xtx (R-A1 cross-tx split) T1 with >= 3 victims, T2 with 2, T3 with 1; foreign_recipient_swap (D10) T1 with
    >= 3 victims in 24 h AND the kit deadline, T2 with either, else T3; kit_signature (S1 / R-A3 selector fingerprint)
    T2 with activity else T3; owner_gated_puller (R-A2) T3 alone, T2 with any behavioural evidence (`active`).
    kit notes K1-K14: batch_approval_drain (K7) / kit_router_swap (K8) / oneshot_multi (K5 hub with >= 3 workers,
    >= 1 leftover return with gas 25 200) = T1; ms_deadline (K4) T1 with any pull label on the same subject, else T2;
    owner_collect (K9) T1 with >= 3 victims, else T2; oneshot_hub (K5), prefund_multi (K12, >= 3 funded workers),
    kit_exact (K2 exact runtime), kit_deposit (K6), cross_chain_t1 (K14 twin of a T1) = T2; prefund_hub, cross_chain,
    gen_back_transfer, eip7702_operator (K13, score boost) = T3.
    kit notes N1-N11: kit_confirmed (N3: a bait victim of a kit public contract, by address or exact runtime),
    ms_cashback (N1: MS_NEW bait in a kit dispatcher with is_cashback = 1), dust_approve_kit (N4 with the kit amount),
    emergency_gas_kit (N5 with the kit amount) = T1; kit_public (N2 exact runtime, no victim seen), ms_cashback_shape
    (N1 calldata only), dust_approve (N4), emergency_gas (N5, flagged spender) = T2; emergency_gas_self (N5, the
    funder approved itself) = T3; kit_vanity (N9) never sets a tier (score only)."""
    if "seed" in labels or "approval_fingerprint" in labels:
        return "T1"
    # TRON T-1..T-8: kit_pull through a kit dispatcher (verify_account etc.), Claimer split with the kit code,
    # outflow signed by a hijacking controller key, mass permission hijack, AML kit approve+transfer x3 = T1
    if "kit_pull" in labels and "kit_signature" in labels:
        return "T1"
    if "claimer_split" in labels and "kit_signature" in labels:
        return "T1"
    if "perm_hijack_drain" in labels:
        return "T1"
    if "aml_approve_transfer" in labels and victims >= 3:
        return "T1"
    if labels & {"approval_kit_shape", "approve_all_call", "aml_approve_transfer", "prefund_approve_multi",
                 "claimer_split", "perm_hijack_multi", "fixed_fee_multi"}:
        return "T2"
    if labels & {"kit_confirmed", "ms_cashback", "dust_approve_kit", "emergency_gas_kit"}:
        return "T1"
    if labels & {"batch_approval_drain", "kit_router_swap", "oneshot_multi"}:
        return "T1"
    if "ms_deadline" in labels and (labels & PULL_LABELS or "ms_deadline_pull" in labels):
        return "T1"
    if "owner_collect" in labels and victims >= OWNER_COLLECTOR_T1_VICTIMS:
        return "T1"
    if "split_pull" in labels and (victims >= 3 or "family_match" in labels):
        return "T1"
    if "bait_payable" in labels and victims >= D7_T1_VICTIMS:
        return "T1"
    if "split_xtx" in labels and victims >= 3:
        return "T1"
    if {"foreign_swap_multi", "foreign_swap_kit"} <= labels:
        return "T1"
    if labels & {"split_pull", "pays_known_operator", "eoa_spender_multi", "bait_payable", "foreign_swap_multi",
                 "foreign_swap_kit", "ms_deadline", "oneshot_hub", "prefund_multi", "owner_collect", "kit_exact",
                 "kit_deposit", "cross_chain_t1", "kit_public", "ms_cashback_shape", "dust_approve", "emergency_gas"}:
        return "T2"
    if "split_xtx" in labels and victims >= 2:
        return "T2"
    if labels & {"family_match", "kit_signature", "owner_gated_puller"} and active:
        return "T2"
    if labels & {"multi_victim_pull", "eoa_spender_pull", "spoof_split", "eip7702_sweeper", "redflag_payable",
                 "redflag_selectors", "family_match", "pays_inferred_operator", "split_xtx", "foreign_recipient_swap",
                 "kit_signature", "owner_gated_puller", "bait_withdraw", "prefund_hub", "cross_chain",
                 "gen_back_transfer", "eip7702_operator", "emergency_gas_self", "kit_pull", "increase_max",
                 "prefund_approve", "perm_hijack", "fixed_fee", "poison_zero"}:
        return "T3"
    return None


def score_of(labels, victims, usd, active):
    s = sum(SCORE[l] for l in labels if l in SCORE)
    if "split_pull" in labels and victims >= 3:
        s += SCORE["victims3"]
    if active:
        s += SCORE["activity"]
    if usd and usd >= 1000:
        s += SCORE["usd_1k"]
    return min(100, s)
