"""Web-research rules W1-W13 (public vendor reports and papers on drainer kits, 2023-2026): pure functions over parsed
receipt logs. The scan wiring lives in scan.web_chunk / scan.eth_block_pass; tiers in detectors.assign_tier.

Parsed extra logs (parse_extra): owner-change events, Seaport OrderFulfilled, ERC-721 transfers, Permit2 permits /
approvals and EIP-3009 AuthorizationUsed. All addresses lower-case."""
from collections import defaultdict

from .constants import (LEGIT_VANITY, POISON_PREFIX, POISON_SUFFIX, SHARE_GRID, SHARE_GRID_TOL, TOPIC_AUTH_USED,
                        TOPIC_LOG_SET_OWNER, TOPIC_OWNERSHIP_TRANSFERRED, TOPIC_P2_APPROVAL, TOPIC_P2_PERMIT,
                        TOPIC_SAFE_ADDED_OWNER, TOPIC_SAFE_CHANGED_THRESHOLD, TOPIC_SAFE_REMOVED_OWNER,
                        TOPIC_SEAPORT_FULFILLED, TOPIC_TRANSFER, VANITY_RE, ZERO)
from .util import addr_of_topic, hx

NFT_ITEM_TYPES = {2, 3, 4, 5}          # Seaport ItemType ERC721 / ERC1155 / *_WITH_CRITERIA
PAY_ITEM_TYPES = {0, 1}                # NATIVE / ERC20


# ---------- W2 / W11 / W10 helpers ----------
def is_vanity(addr) -> bool:
    """>= 4 leading and >= 4 trailing zero nibbles (and not a legitimate contract with that shape)."""
    a = (addr or "").lower()
    return bool(VANITY_RE.match(a)) and a not in LEGIT_VANITY


def grid_share(share):
    """W11: the documented DaaS share (0.70 / 0.80 / 0.85 / 0.90) within +-0.5 points, else None."""
    if share is None:
        return None
    for g in SHARE_GRID:
        if abs(share - g) <= SHARE_GRID_TOL + 1e-12:
            return g
    return None


def lookalike(a, b, pre=POISON_PREFIX, suf=POISON_SUFFIX) -> bool:
    """W10: b imitates a: different addresses with the same first `pre` and last `suf` hex characters."""
    a, b = (a or "").lower(), (b or "").lower()
    return len(a) == len(b) == 42 and a != b and a[2:2 + pre] == b[2:2 + pre] and a[-suf:] == b[-suf:]


# ---------- log parsing ----------
def _word(data: bytes, i: int) -> int:
    return int.from_bytes(data[32 * i: 32 * i + 32], "big")


def _a(v: int) -> str:
    return "0x" + f"{v & ((1 << 160) - 1):040x}"


def _data(lg) -> bytes:
    d = lg.get("data") or "0x"
    try:
        return bytes.fromhex(d[2:] if d.startswith("0x") else d)
    except ValueError:
        return b""


def decode_order_fulfilled(lg):
    """Seaport OrderFulfilled(bytes32 orderHash, address indexed offerer, address indexed zone, address recipient,
    SpentItem[] offer, ReceivedItem[] consideration) -> dict or None (malformed)."""
    t = lg.get("topics") or []
    b = _data(lg)
    if len(t) != 3 or len(b) < 128:
        return None
    try:
        rcpt, oo, co = _word(b, 1), _word(b, 2), _word(b, 3)
        if rcpt >> 160:
            return None

        def arr(off, width):
            n = int.from_bytes(b[off:off + 32], "big")
            if n > 200 or off + 32 + 32 * width * n > len(b):
                raise ValueError
            base = off + 32
            return [[int.from_bytes(b[base + 32 * (width * i + j): base + 32 * (width * i + j) + 32], "big")
                     for j in range(width)] for i in range(n)]
        offer = [dict(item_type=x[0], token=_a(x[1]), ident=x[2], amount=x[3]) for x in arr(oo, 4)]
        cons = [dict(item_type=x[0], token=_a(x[1]), ident=x[2], amount=x[3], recipient=_a(x[4])) for x in arr(co, 5)]
    except (ValueError, IndexError):
        return None
    return dict(tx=lg["transactionHash"], block=hx(lg.get("blockNumber")), li=hx(lg.get("logIndex")),
                contract=(lg.get("address") or "").lower(), offerer=addr_of_topic(t[1]), zone=addr_of_topic(t[2]), recipient=_a(rcpt), offer=offer, consideration=cons)


def parse_extra(logs):
    """Receipt logs -> dict(owner=[...], seaport=[...], nft=[...], p2=[...], auth_txs=set()). Unknown shapes skipped."""
    out = dict(owner=[], seaport=[], nft=[], p2=[], auth_txs=set())
    for lg in logs:
        t = lg.get("topics") or []
        if not t:
            continue
        t0 = t[0]
        base = dict(tx=lg["transactionHash"], block=hx(lg.get("blockNumber")), li=hx(lg.get("logIndex")),
                    contract=(lg.get("address") or "").lower())
        if t0 == TOPIC_TRANSFER and len(t) == 4:
            out["nft"].append(dict(base, token=base["contract"], frm=addr_of_topic(t[1]), to=addr_of_topic(t[2]),
                                   ident=int(t[3], 16)))
        elif t0 == TOPIC_OWNERSHIP_TRANSFERRED and len(t) == 3:
            out["owner"].append(dict(base, kind="ownership", prev=addr_of_topic(t[1]), new=addr_of_topic(t[2])))
        elif t0 == TOPIC_LOG_SET_OWNER and len(t) == 2:
            out["owner"].append(dict(base, kind="set_owner", prev=None, new=addr_of_topic(t[1])))
        elif t0 in (TOPIC_SAFE_ADDED_OWNER, TOPIC_SAFE_REMOVED_OWNER):
            b = _data(lg)
            who = addr_of_topic(t[1]) if len(t) == 2 else (_a(_word(b, 0)) if len(b) >= 32 else None)
            if who:
                out["owner"].append(dict(base, kind="safe_added" if t0 == TOPIC_SAFE_ADDED_OWNER else "safe_removed",
                                         prev=None, new=who))
        elif t0 == TOPIC_SAFE_CHANGED_THRESHOLD:
            b = _data(lg)
            if len(b) >= 32:
                out["owner"].append(dict(base, kind="safe_threshold", prev=None, new=None, threshold=_word(b, 0)))
        elif t0 == TOPIC_SEAPORT_FULFILLED:
            d = decode_order_fulfilled(lg)
            if d:
                out["seaport"].append(d)
        elif t0 in (TOPIC_P2_PERMIT, TOPIC_P2_APPROVAL) and len(t) == 4:
            out["p2"].append(dict(base, owner=addr_of_topic(t[1]), token=addr_of_topic(t[2]), spender=addr_of_topic(t[3]),
                                  kind="permit2", value=1))
        elif t0 == TOPIC_AUTH_USED:
            out["auth_txs"].add(base["tx"])
    return out


# ---------- W1 deploy-and-drain ----------
def toplevel_deploy_drain(transfers, txmeta):
    """W1a: a top-level contract creation (receipt contractAddress C) whose own tx moves a third party's tokens
    (Transfer.from = V, V not tx.from, not C, value > 0). Returns [dict(created, deployer, tx, block, legs)]."""
    created = {h: m for h, m in txmeta.items() if m.get("created") and m.get("status", 1) == 1}
    if not created:
        return []
    by_tx = defaultdict(list)
    for t in transfers:
        if t["tx"] in created and t["value"] > 0 and t["frm"] != ZERO:
            m = created[t["tx"]]
            if t["frm"] not in (m["from"], m["created"]):
                by_tx[t["tx"]].append(t)
    return [dict(created=created[h]["created"], deployer=created[h]["from"], tx=h, block=legs[0]["block"], legs=legs)
            for h, legs in by_tx.items()]


def permit_pull_candidates(transfers, approvals, txs, is_allowed):
    """W1b: one tx carries an Approval(owner V, spender S) and a Transfer out of V (a permit executed and used in the
    same tx), V is not tx.from, S is not tx.from, tx.to is not allowlisted. The caller then checks whether S had code
    before the tx (created inside it). Returns [dict(tx, block, victim, spender, tx_to, tx_from, legs)]."""
    out = {}
    aps = defaultdict(set)
    for a in approvals:
        if a.get("kind", "approval") == "approval" and a["value"] > 0:
            aps[(a["tx"], a["owner"])].add(a["spender"])
    for t in transfers:
        if t["value"] == 0 or t["frm"] == ZERO:
            continue
        tx = txs.get(t["tx"])
        sp = aps.get((t["tx"], t["frm"]))
        if not tx or not sp or not tx.get("to"):
            continue
        frm, to = tx["from"], tx["to"]
        if t["frm"] in (frm, to) or is_allowed(to) or is_allowed(t["frm"]):
            continue
        for s in sp:
            if s in (frm, ZERO, t["frm"]) or is_allowed(s):
                continue
            k = (t["tx"], t["frm"], s)
            out.setdefault(k, dict(tx=t["tx"], block=t["block"], victim=t["frm"], spender=s, tx_to=to, tx_from=frm,
                                   legs=[]))["legs"].append(t)
    return list(out.values())


def ghost_candidates(transfers, approvals, txs, auth_txs, is_allowed):
    """W1c: tokens leave address C in a tx that C did not send, with no Approval by C in that tx, not through the token
    itself or Permit2/an allowlisted contract and without an EIP-3009 authorization. The caller keeps those whose C has
    neither code nor any sent tx (nonce 0) today: code that existed only inside that tx (deployed and self-destructed
    there, e.g. a pre-computed CREATE2 address that received the victim's tokens first). Returns {(tx_to, C): [legs]}."""
    approved = {(a["tx"], a["owner"]) for a in approvals}
    out = defaultdict(list)
    for t in transfers:
        if t["value"] == 0 or t["frm"] == ZERO or t["to"] == ZERO:
            continue
        tx = txs.get(t["tx"])
        if not tx or not tx.get("to") or t["tx"] in auth_txs:
            continue
        c, frm, to = t["frm"], tx["from"], tx["to"]
        if c in (frm, to) or to == t["token"] or (t["tx"], c) in approved or is_allowed(to) or is_allowed(c):
            continue
        out[(to, c)].append(t)
    return out


# ---------- W5 owner takeover ----------
def owner_changes(events, txs):
    """W5: owner-change events -> pending takeovers dict(contract, new_owner, prev, change_tx, block, signer, kind).
    OwnershipTransferred from the zero address (construction) and renounces are skipped; DSProxy LogSetOwner and
    Safe AddedOwner are kept only when the new owner is not the tx sender (the victim signs, the attacker gains)."""
    out = []
    safe_tx = defaultdict(list)
    for e in events:
        if e["kind"] in ("safe_removed", "safe_threshold"):
            safe_tx[(e["tx"], e["contract"])].append(e)
    for e in events:
        if e["kind"] not in ("ownership", "set_owner", "safe_added"):
            continue
        new = e["new"]
        if not new or new == ZERO or (e["kind"] == "ownership" and (e["prev"] in (None, ZERO) or e["prev"] == new)):
            continue
        signer = (txs.get(e["tx"]) or {}).get("from")
        if signer == new:
            continue
        d = dict(contract=e["contract"], new_owner=new, prev=e["prev"], change_tx=e["tx"], block=e["block"],
                 signer=signer, kind=e["kind"])
        if e["kind"] == "safe_added":
            ex = safe_tx.get((e["tx"], e["contract"]), [])
            d["removed"] = [x["new"] for x in ex if x["kind"] == "safe_removed"]
            d["threshold"] = next((x["threshold"] for x in ex if x["kind"] == "safe_threshold"), None)
            if not d["removed"] and d["threshold"] != 1:
                continue                     # an added co-signer without control: ordinary Safe administration
        out.append(d)
    return out


def takeover_hits(pending, transfers, txs):
    """Outflows (Transfer.from = contract) sent by the new owner after the change. Returns [(pending, [legs])]."""
    by_key = defaultdict(list)
    for t in transfers:
        tx = txs.get(t["tx"])
        if tx and t["value"] > 0:
            by_key[(t["frm"], tx["from"])].append(t)
    out = []
    for p in pending:
        legs = [t for t in by_key.get((p["contract"], p["new_owner"]), ()) if t["block"] >= p["block"]
                and t["to"] != p["contract"]]
        if legs:
            out.append((p, legs))
    return out


# ---------- W7 NFT ----------
def seaport_zero(ev):
    """W7: Seaport order whose offer contains NFTs while the offerer receives no native / ERC-20 consideration at all
    (zero-price listing signed by the victim) and the NFTs go to someone else. Returns detail dict or None."""
    nfts = [x for x in ev["offer"] if x["item_type"] in NFT_ITEM_TYPES]
    if not nfts or ev["recipient"] in (ev["offerer"], ZERO):
        return None
    paid = sum(c["amount"] for c in ev["consideration"] if c["recipient"] == ev["offerer"] and c["item_type"] in PAY_ITEM_TYPES)
    if paid:
        return None
    if any(c["recipient"] == ev["offerer"] for c in ev["consideration"]):
        return None                          # the offerer gets an NFT / item back: a swap, not a giveaway
    return dict(victim=ev["offerer"], fulfiller=ev["recipient"], nfts=[dict(token=x["token"], ident=str(x["ident"]))
                                                                       for x in nfts[:10]], n_nfts=len(nfts))


def nft_operator_pulls(pending_ops, nft_transfers, txs):
    """W7 setApprovalForAll to an EOA operator X (pending: (owner, operator) -> (tx, block)), then ERC-721 transfers of
    the owner's NFTs in txs sent by X. Returns {(operator, owner): [transfers]}."""
    out = defaultdict(list)
    for t in nft_transfers:
        tx = txs.get(t["tx"])
        if not tx:
            continue
        k = (t["frm"], tx["from"])
        if k in pending_ops and t["block"] >= pending_ops[k][1] and t["to"] != t["frm"]:
            out[(tx["from"], t["frm"])].append(t)
    return out


# ---------- W8b phishing batch through a delegated EOA ----------
def batch7702_tx(owner, approvals, transfers, is_allowed):
    """W8b: one self-call of a delegated EOA (tx.from == tx.to == owner). Legs = approvals / ApprovalForAll by the owner
    (value > 0) and token transfers out of the owner, to non-allowlisted counterparties. Flag when >= 2 legs, at least
    one approval, and nothing came back to the owner. Returns dict(spenders, recipients, legs) or None; the caller keeps
    counterparties that are EOAs."""
    aps = [a for a in approvals if a["owner"] == owner and a["value"] > 0 and a["spender"] not in (owner, ZERO)
           and not is_allowed(a["spender"])]
    outs = [t for t in transfers if t["frm"] == owner and t["value"] > 0 and t["to"] not in (owner, ZERO)
            and not is_allowed(t["to"])]
    if not aps or len(aps) + len(outs) < 2:
        return None
    if any(t["to"] == owner and t["value"] > 0 for t in transfers):
        return None
    tokens = {t["token"] for t in transfers} | {a["token"] for a in approvals}
    sp = sorted({a["spender"] for a in aps} - tokens)
    rc = sorted({t["to"] for t in outs} - tokens)
    if not sp:
        return None
    return dict(spenders=sp, recipients=rc, approvals=[dict(spender=a["spender"], token=a["token"], kind=a.get("kind"))
                                                       for a in aps[:10]],
                legs=[dict(token=t["token"], to=t["to"], value=str(t["value"])) for t in outs[:10]])


# ---------- W10 zero-value poisoning on real stablecoins ----------
def zero_poison_legs(transfers, txs, stables):
    """Zero-value Transfer of a real stablecoin out of V where V is neither tx.from nor tx.to (someone else's
    transferFrom(V, L, 0)). Subject = tx.to (the bundler contract), or tx.from when it called the token directly.
    Returns {subject: [legs]}."""
    out = defaultdict(list)
    for t in transfers:
        if t["value"] != 0 or t["token"] not in stables or t["frm"] in (ZERO, t["to"]):
            continue
        tx = txs.get(t["tx"])
        if not tx or not tx.get("to") or t["frm"] in (tx["from"], tx["to"]):
            continue
        subject = tx["from"] if tx["to"] == t["token"] else tx["to"]
        out[subject].append(t)
    return out
