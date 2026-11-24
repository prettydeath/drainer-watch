"""TRON drainer rules T-1..T-8 as pure functions over parsed blocks (tron.parse_block) and tx-info logs
(tron.parse_infos). Addresses are base58 (T...). The I/O-bound parts (contract code, account age, balances, signer
recovery) are done by tron_scan, which feeds the results back in through small callables."""
from collections import defaultdict

from .constants import (APPROVE_SELECTORS, BAIT_ADDR_SELECTORS, TRON_AML_FEE_LIMIT,
                        TRON_APPROVE_ALL_SELECTOR, TRON_CLAIMER_KEEP_SUN, TRON_CLAIMER_SHARE, TRON_CLAIMER_TOL,
                        TRON_FEE_MAX_SUN, TRON_FEE_MIN_SUN, TRON_FEE_WINDOW, TRON_KIT_AMOUNTS, TRON_PERM_MIN_AGE_SEC, UINT256_MAX)
from .tron import TRON_ZERO, word_addr

SEL_TRANSFER = "a9059cbb"


# ---------- calldata ----------
def sel_of(tx):
    return (tx.get("data") or "")[:8]


def arg_word(data, i):
    s = data[8 + 64 * i: 8 + 64 * (i + 1)]
    return s if len(s) == 64 else None


def decode_approve(tx):
    """approve / increaseApproval / increaseAllowance / daea85c5(address) on a token -> (method, spender, amount|None)."""
    data, sel = tx.get("data") or "", sel_of(tx)
    if sel == TRON_APPROVE_ALL_SELECTOR:
        w = arg_word(data, 0)
        return ("approve_all", word_addr(w), None) if w else None
    if sel in APPROVE_SELECTORS:
        w0, w1 = arg_word(data, 0), arg_word(data, 1)
        if w0 and w1:
            return APPROVE_SELECTORS[sel], word_addr(w0), int(w1, 16)
    return None


def decode_transfer(tx):
    data = tx.get("data") or ""
    if sel_of(tx) != SEL_TRANSFER:
        return None
    w0, w1 = arg_word(data, 0), arg_word(data, 1)
    return (word_addr(w0), int(w1, 16)) if w0 and w1 else None


# ---------- T-1 / T-2 third-party pulls ----------
def third_party_pulls(transfers, txs):
    """Transfer legs moved by somebody else: Transfer.from (victim) is neither the tx signer nor tx.to, value > 0, no
    mint/burn. Returns legs with caller (tx signer), via ('token' when tx.to is the token itself = EOA spender, else
    'contract') and subject (caller for EOA spenders, tx.to for puller contracts)."""
    out = []
    for t in transfers:
        tx = txs.get(t["tx"])
        if not tx or not tx.get("ok") or t["value"] == 0 or TRON_ZERO in (t["frm"], t["to"]):
            continue
        caller, to = tx.get("frm"), tx.get("to")
        if not to or t["frm"] in (caller, to) or t["to"] == t["frm"]:
            continue
        via = "token" if to == t["token"] else "contract"
        out.append(dict(t, caller=caller, via=via, subject=caller if via == "token" else to))
    return out


# ---------- T-3 approval fingerprints ----------
def approval_calls(txs):
    """Successful approve-family calls on a token contract: [dict(tx, owner, token, spender, amount, method, fee_limit,
    block, ts)]."""
    out = []
    for tx in txs:
        if tx.get("type") != "TriggerSmartContract" or not tx.get("ok"):
            continue
        dec = decode_approve(tx)
        if not dec or not dec[1] or dec[1] in (tx["frm"], TRON_ZERO):
            continue
        out.append(dict(tx=tx["h"], owner=tx["frm"], token=tx["to"], spender=dec[1], amount=dec[2], method=dec[0],
                        fee_limit=tx.get("fee_limit") or 0, block=tx["block"], ts=tx["ts"]))
    return out


def approval_kind(c):
    """Kit shape of one approval call (kit notes K10): 'kit_amount' (10^46: usdaudit / bybit-scan), 'approve_all'
    (daea85c5(address)), 'increase_max' (increaseApproval 2^256-1) or 'aml_exact' candidate (plain approve with the
    kit's 300 TRX feeLimit; confirmed only by a following transfer to the spender). None otherwise."""
    if c["method"] == "approve_all":
        return "approve_all"
    amt = c["amount"]
    if amt in TRON_KIT_AMOUNTS:
        return "kit_amount"
    if c["method"] == "increaseApproval" and amt == UINT256_MAX:
        return "increase_max"
    if c["method"] == "approve" and c["fee_limit"] == TRON_AML_FEE_LIMIT and amt and amt != UINT256_MAX:
        return "aml_exact"
    return None


def aml_followups(cands, txs):
    """K10 AML kit: approve(spender, exact balance) with feeLimit 300 TRX, then the victim itself calls
    transfer(spender, 0 | approved amount) on the same token (the bait transfer). cands: approval calls of kind
    'aml_exact'; txs: parsed txs (current chunk + carry). Returns [(cand, transfer_tx)]."""
    by_owner = defaultdict(list)
    for tx in txs:
        if tx.get("type") == "TriggerSmartContract" and tx.get("ok") and sel_of(tx) == SEL_TRANSFER:
            by_owner[(tx["frm"], tx["to"])].append(tx)
    out = []
    for c in cands:
        for tx in by_owner.get((c["owner"], c["token"]), ()):
            dec = decode_transfer(tx)
            if dec and dec[0] == c["spender"] and dec[1] in (0, c["amount"]) and 0 <= tx["ts"] - c["ts"] <= 600:
                out.append((c, tx))
                break
    return out


# ---------- T-4 pre-funding ----------
def small_fundings(txs, lo_sun, hi_sun):
    """Plain TRX transfers with a whole-TRX amount in [lo, hi] sun: [(funder, recipient, amount, tx, ts, block)]."""
    return [(t["frm"], t["to"], t["amount"], t["h"], t["ts"], t["block"]) for t in txs
            if t.get("type") == "TransferContract" and t.get("ok") and lo_sun <= t["amount"] <= hi_sun
            and t["amount"] % 1_000_000 == 0 and t["frm"] != t["to"]]


# ---------- T-5 Claimer ----------
def bait_calls(txs):
    """Payable bait(address) calls with TRX attached: [dict(tx, victim, contract, name, customer, value, block, ts)]."""
    out = []
    for tx in txs:
        if tx.get("type") != "TriggerSmartContract" or not tx.get("ok") or tx.get("call_value", 0) <= 0:
            continue
        s = sel_of(tx)
        if s not in BAIT_ADDR_SELECTORS:
            continue
        w = arg_word(tx["data"], 0)
        out.append(dict(tx=tx["h"], victim=tx["frm"], contract=tx["to"], name=BAIT_ADDR_SELECTORS[s],
                        customer=word_addr(w) if w else None, value=tx["call_value"], block=tx["block"], ts=tx["ts"]))
    return out


def claimer_shape(value, balance_after, fee=0):
    """kasumi 'Claimer' (K11): callValue = min(balance - 50 TRX, 0.8 * balance) with balance = before the call.
    balance_after: the account's TRX balance right after the call (sun). True / False / None (unknown)."""
    if balance_after is None:
        return None
    before = balance_after + value + fee
    if before <= 0:
        return None
    want = min(before - TRON_CLAIMER_KEEP_SUN, int(TRON_CLAIMER_SHARE * before))
    return abs(value - want) <= max(TRON_CLAIMER_TOL * before, 2_000_000)


# ---------- T-6 AccountPermissionUpdate ----------
def _keys(perm):
    return [(k.get("address"), int(k.get("weight") or 0)) for k in (perm or {}).get("keys") or []]


def own_sufficient(perm, account):
    """True if the account's own key alone still satisfies this permission (missing permission = default = own key)."""
    if not perm:
        return True
    th = int(perm.get("threshold") or 1)
    return sum(w for a, w in _keys(perm) if a == account) >= th


def own_weight(perm, account):
    return sum(w for a, w in _keys(perm) if a == account)


def takeover_shape(perm, account):
    """'single_key': one foreign key alone satisfies the threshold (owner/active handed to an attacker key, SlowMist);
    'cosign_lock': the account's key is still listed but below the threshold and one foreign key completes it (FreezeRadar:
    the attacker adds its key and raises the threshold). None when only several foreign keys together can sign: that is
    an organisation's multisig (custodial key migrations of old service accounts look exactly like that)."""
    th = int((perm or {}).get("threshold") or 1)
    own = own_weight(perm, account)
    foreign = [w for a, w in _keys(perm) if a and a != account]
    if any(w >= th for w in foreign):
        return "single_key"
    if 0 < own < th and any(own + w >= th for w in foreign):
        return "cosign_lock"
    return None


def perm_change(tx):
    """AccountPermissionUpdate -> dict(victim, controllers, owner_lost, active_lost, threshold, own_weight, keys) when
    the account's own key is no longer sufficient for the owner permission or for every active permission; else None.
    controllers = foreign keys, heaviest first."""
    p = tx.get("perm")
    if tx.get("type") != "AccountPermissionUpdateContract" or not p or not tx.get("ok"):
        return None
    acc = tx["frm"]
    owner = p.get("owner") or {}
    actives = p.get("actives") or []
    owner_lost = not own_sufficient(owner, acc)
    active_lost = bool(actives) and all(not own_sufficient(a, acc) for a in actives)
    if not (owner_lost or active_lost):
        return None
    w = defaultdict(int)
    for perm in [owner] + list(actives):
        for a, wt in _keys(perm):
            if a and a != acc:
                w[a] = max(w[a], wt)
    if not w:
        return None
    ctrl = sorted(w, key=lambda a: (-w[a], a))
    shape = takeover_shape(owner if owner_lost else min(actives, key=lambda p: own_weight(p, acc)), acc)
    if not shape:
        return None
    return dict(victim=acc, controllers=ctrl, owner_lost=owner_lost, active_lost=active_lost, shape=shape,
                threshold=int(owner.get("threshold") or 1),
                own_weight=sum(wt for a, wt in _keys(owner) if a == acc), keys=len(_keys(owner)))


def perm_signal(change, victim_created_ts, tx_ts, key_history):
    """Bitquery conditions: the change happens >= 30 days after the account's first activity (same-day changes are
    wallet setup noise) and is a real takeover (own key insufficient). key_history: {key: bool has history|None}."""
    if victim_created_ts is None or tx_ts - victim_created_ts < TRON_PERM_MIN_AGE_SEC:
        return None
    fresh = [k for k in change["controllers"] if key_history.get(k) is False]
    return dict(change, age_days=int((tx_ts - victim_created_ts) // 86400), fresh_keys=fresh)


# ---------- T-7 fixed TRX fee after a pull ----------
def fixed_fees(pulls, txs, window=TRON_FEE_WINDOW):
    """A pull of a third party's tokens followed within `window` seconds by a whole-TRX transfer >= TRON_FEE_MIN_SUN
    from the same caller (or from the pull recipient) to an address that is not the victim / recipient. Each fee
    transfer is matched to the nearest preceding pull of its payer. Returns [dict(fee_to, amount, caller, victim,
    pull_tx, fee_tx, block)]; aggregation across hits is the rollup's job."""
    by_payer = defaultdict(list)
    for p in pulls:
        for payer in {p["caller"], p["to"]}:
            by_payer[payer].append(p)
    out = []
    for f in txs:
        if f.get("type") != "TransferContract" or not f.get("ok") or not TRON_FEE_MIN_SUN <= f["amount"] <= TRON_FEE_MAX_SUN                 or f["amount"] % 1_000_000:
            continue
        cands = [p for p in by_payer.get(f["frm"], ()) if 0 <= f["ts"] - p["ts"] <= window and p["tx"] != f["h"]
                 and f["to"] not in (p["frm"], p["to"], p["caller"], p["subject"])]
        if not cands:
            continue
        p = max(cands, key=lambda x: (x["ts"], x["block"], x["li"]))
        out.append(dict(fee_to=f["to"], amount=f["amount"], caller=p["caller"], victim=p["frm"], pull_tx=p["tx"],
                        fee_tx=f["h"], block=f["block"]))
    return out


# ---------- T-8 zero-value poisoning ----------
def zero_transfers(transfers, txs, tokens):
    """Zero-value Transfer of a watched token (USDT) where the signer is not Transfer.from: address-poisoning
    transferFrom(victim, lookalike, 0). subject = tx.to when it is a contract call other than the token, else signer.
    Returns {subject: [legs]}."""
    out = defaultdict(list)
    for t in transfers:
        if t["value"] != 0 or t["token"] not in tokens:
            continue
        tx = txs.get(t["tx"])
        if not tx or t["frm"] == tx.get("frm") or TRON_ZERO in (t["frm"], t["to"]):
            continue
        subject = tx["frm"] if tx.get("to") == t["token"] else tx.get("to")
        if subject:
            out[subject].append(t)
    return out

