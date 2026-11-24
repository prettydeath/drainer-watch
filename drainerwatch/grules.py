"""GitHub / paper research rules G1-G13 (public detection bots, academic datasets and vendor reports on drainers and
address poisoning, 2023-2026): pure functions. Scan wiring in gscan.py, tiers in detectors.assign_tier (G_T2 / G_T3),
labels in rollup.py. All addresses lower-case; parsed transfers / approvals as in detectors.py."""
from collections import Counter, defaultdict

from . import bytecode
from .constants import (FAKE_CALL_SELECTORS, FUNDERS_BAND, FUNDERS_MIN, LOOKALIKE_CONTRACT_PRE, LOOKALIKE_CONTRACT_SUF,
                        NFT_BULK_MIN_ITEMS, PHISH_MAX_EVENTS, PHISH_MAX_FUNCS, PHISH_MULTICALL_SELECTORS,
                        PHISH_PULL_SELECTORS, POISON_TYPO_CHARS, ROUTER_SWEEP_MIN_SHARE, SEAPORT_FEE_MAX_OFFERER_SHARE,
                        SEAPORT_NEAR_ZERO_WEI, SEL_BALANCE_OF, ZERO)
from .wrules import NFT_ITEM_TYPES, PAY_ITEM_TYPES


# ---------- G1 fake-function native call ----------
def fake_call_name(inp, value):
    """G1: input is exactly one 4-byte selector of a kit bait name and value > 0 -> the name, else None."""
    if not value or value <= 0 or not inp or len(inp) != 10:
        return None
    return FAKE_CALL_SELECTORS.get(inp[2:10].lower())


def is_round(value_wei: int) -> bool:
    """A 'round' native amount (<= 3 decimals of the native coin): deliberate payments, not a balance being emptied."""
    return value_wei > 0 and value_wei % 10 ** 15 == 0


def fake_call_keep(rows, near_senders):
    """Public detection-bot false-positive filters on G1 rows (h, to, name, value, frm, block): drop senders that sent
    another tx within FAKE_CALL_NEAR_BLOCKS (near_senders = set of such senders), and round values unless the recipient
    got several different amounts (several victims). Returns the kept rows."""
    by_to = defaultdict(set)
    for r in rows:
        by_to[r[1]].add(r[3])
    return [r for r in rows if r[4] not in near_senders and (not is_round(r[3]) or len(by_to[r[1]]) >= 2)]


# ---------- G2 many funders into one fresh EOA ----------
def funders_hit(funds, min_funders=FUNDERS_MIN, band=FUNDERS_BAND):
    """G2 (public NIP-4 / NIP-7 rules): funds = [(funder, value, nonce, tx, block)] into one recipient within the window.
    Hit when >= min_funders distinct funders paid amounts within band x median, and no single funder nonce is shared by
    more than a third of them (a same-nonce batch = one operator's sybil wallets consolidating). Returns dict or None."""
    best = {}
    for f, v, n, h, b in funds:
        if v > 0 and (f not in best or b > best[f][3]):
            best[f] = (v, n, h, b)
    if len(best) < min_funders:
        return None
    vals = sorted(x[0] for x in best.values())
    med = vals[len(vals) // 2]
    inband = {f: x for f, x in best.items() if band[0] * med <= x[0] <= band[1] * med}
    if len(inband) < min_funders:
        return None
    nonces = Counter(x[1] for x in inband.values())
    if nonces.most_common(1)[0][1] * 3 > len(inband):
        return None
    last = max(inband.values(), key=lambda x: x[3])
    return dict(funders=sorted(inband), median_wei=str(med), tx=last[2], block=last[3], n=len(inband))


# ---------- G3 deploy-time phishing contract ----------
def phish_traits(code_hex):
    """G3 (public NIP-8 rule): runtime without balanceOf, <= 1 event, <= 10 dispatcher functions and a multicall of
    (address,bytes)[] / (address[],bytes[]). Returns the multicall names or None."""
    code = bytecode.to_bytes(code_hex)
    if not code or bytecode.is_delegated_eoa(code_hex):
        return None
    sels = set(bytecode.selectors_of(code))
    mc = sorted(PHISH_MULTICALL_SELECTORS[s] for s in sels if s in PHISH_MULTICALL_SELECTORS)
    if not mc or SEL_BALANCE_OF in sels or len(sels) > PHISH_MAX_FUNCS or bytecode.log_count(code) > PHISH_MAX_EVENTS:
        return None
    return mc


def inner_selectors(inp):
    """Selectors of the calls packed in multicall calldata: every 4-byte word that starts a bytes element. Cheap scan:
    any known pull selector appearing at a 32-byte boundary + 32 (length word) of the payload."""
    b = inp[10:] if inp and inp.startswith("0x") else (inp or "")
    out = set()
    for i in range(0, len(b) - 8, 64):
        w = b[i:i + 8].lower()
        if w in PHISH_PULL_SELECTORS:
            out.add(w)
    return out


# ---------- G4 trusted-router pull + sweep ----------
def router_sweeps(transfers, txs, routers):
    """G4: a tx to a trusted router in which tokens of tx.from go into the router and leave it to a third address
    (not tx.from), with ONE token moving in the whole tx (no swap in between) and >= 95 % of what came in leaving to
    third parties. Returns [dict(tx, block, victim, router, token, recipients, legs_in, legs_out)]."""
    by_tx = defaultdict(list)
    for t in transfers:
        tx = txs.get(t["tx"])
        if tx and tx.get("to") in routers and t["value"] > 0:
            by_tx[t["tx"]].append(t)
    out = []
    for h, legs in by_tx.items():
        tx = txs[h]
        frm, router = tx["from"], tx["to"]
        if len({t["token"] for t in legs}) != 1:
            continue
        ins = [t for t in legs if t["frm"] == frm]
        outs = [t for t in legs if t["frm"] == router and t["to"] not in (frm, router, ZERO)]
        if not ins or not outs or any(t["to"] == frm for t in legs):
            continue
        vin, vout = sum(t["value"] for t in ins), sum(t["value"] for t in outs)
        if vout < ROUTER_SWEEP_MIN_SHARE * vin:
            continue
        out.append(dict(tx=h, block=legs[0]["block"], victim=frm, router=router, token=legs[0]["token"],
                        recipients=sorted({t["to"] for t in outs}), legs_in=ins, legs_out=outs))
    return out


# ---------- G5 NFT ----------
def nft_bulk(nft_transfers, txs, helpers, min_items=NFT_BULK_MIN_ITEMS):
    """G5: NFT transfers of tx.from to one other address in a tx sent to the Seaport TransferHelper (bulkTransfer).
    Returns {(recipient, victim): [transfers]} with >= min_items items."""
    out = defaultdict(list)
    for t in nft_transfers:
        tx = txs.get(t["tx"])
        if tx and tx.get("to") in helpers and t["frm"] == tx["from"] and t["to"] not in (tx["from"], ZERO):
            out[(t["to"], t["frm"])].append(t)
    return {k: v for k, v in out.items() if len(v) >= min_items}


def seaport_fee_drain(ev, wrapped=()):
    """G5: Seaport order whose offer holds NFTs, fulfilled for someone else, where the offerer receives <= 1 % of the
    payment (fees ~100 %) and the whole price is near zero (<= 0.001 native / wrapped native; other payment tokens are
    not judged). Gifts and private sales can have recipient != offerer, hence the price condition. W7 covers price 0."""
    nfts = [x for x in ev["offer"] if x["item_type"] in NFT_ITEM_TYPES]
    if not nfts or ev["recipient"] in (ev["offerer"], ZERO):
        return None
    pay = [c for c in ev["consideration"] if c["item_type"] in PAY_ITEM_TYPES]
    if not pay or any(c["item_type"] == 1 and c["token"] not in wrapped for c in pay):
        return None
    total = sum(c["amount"] for c in pay)
    own = sum(c["amount"] for c in pay if c["recipient"] == ev["offerer"])
    if total == 0 or own == 0 or total > SEAPORT_NEAR_ZERO_WEI or own > SEAPORT_FEE_MAX_OFFERER_SHARE * total:
        return None
    fee_to = sorted({c["recipient"] for c in pay if c["recipient"] != ev["offerer"]})
    return dict(victim=ev["offerer"], fulfiller=ev["recipient"], price_wei=str(total), offerer_share=round(own / total, 4),
                fee_to=fee_to[:3], n_nfts=len(nfts), nfts=[dict(token=x["token"], ident=str(x["ident"])) for x in nfts[:10]])


# ---------- G6 address poisoning ----------
def similarity(a, b):
    """Matching leading + trailing hex characters of two addresses (CMU study: similarity)."""
    a, b = (a or "").lower()[2:], (b or "").lower()[2:]
    if len(a) != 40 or len(b) != 40 or a == b:
        return 0
    pre = next((i for i in range(40) if a[i] != b[i]), 40)
    suf = next((i for i in range(40) if a[39 - i] != b[39 - i]), 40)
    return pre + suf


def lookalike_of(addr, partners, pre=3, suf=4):
    """The partner `addr` imitates (same first `pre` and last `suf` hex chars, not a typo with >= 20 matching chars)."""
    a = (addr or "").lower()
    for r in partners:
        if r != a and a[2:2 + pre] == r[2:2 + pre] and a[-suf:] == r[-suf:] and similarity(a, r) < POISON_TYPO_CHARS:
            return r
    return None


def attack_ratio(subject_txs, attack_txs):
    """CMU filter: share of a sender's txs in view that are poisoning txs."""
    return len(attack_txs & subject_txs) / len(subject_txs) if subject_txs else 1.0


def poison_batch(legs, n_known, nlogs, stables, spoof):
    """G6 batched poisoning tx: every log of the tx is Transfer / Approval (nlogs = all logs of the receipt), >= 6
    transfers (n_known = its Transfer + Approval logs), most of them on real stablecoins or counterfeit tokens, and the amounts repeat (<= n/2 distinct values)
    or counterfeit tokens are minted from 0x0 in the same tx. Returns a detail dict or None."""
    n = len(legs)
    if n < 6 or nlogs is None or nlogs != n_known:
        return None
    st = [t for t in legs if t["token"] in stables or t["token"] in spoof]
    if len(st) * 2 < n:
        return None
    distinct = len({t["value"] for t in legs})
    mints = sum(1 for t in legs if t["frm"] == ZERO and t["token"] in spoof)
    if distinct * 2 > n and not mints:
        return None
    return dict(legs=n, distinct_values=distinct, spoof_mints=mints, stable_legs=len(st))


class UF:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def poison_clusters(items):
    """G6 clustering (CMU): items = [(subject, [shared keys: tx hashes, lookalike addresses, attacker wallets])]; subjects
    sharing a key are one campaign. Fake-token contracts / attack contracts are NOT keys (shared across campaigns).
    Returns subject -> root subject."""
    uf = UF()
    for s, keys in items:
        uf.find(("s", s))
        for k in keys:
            uf.union(("s", s), ("k", k))
    return {s: "%s:%s" % uf.find(("s", s)) for s, _ in items}


# ---------- G7 lookalike contract creation ----------
def lookalike_contract(created, busy, pre=LOOKALIKE_CONTRACT_PRE, suf=LOOKALIKE_CONTRACT_SUF):
    """G7: a newly created contract sharing the first `pre` and last `suf` hex characters with a busy contract."""
    c = created.lower()
    for b in busy:
        if b != c and c[2:2 + pre] == b[2:2 + pre] and c[-suf:] == b[-suf:]:
            return b
    return None


# ---------- G8 counterfactual destination ----------
def counterfactual_keep(legs, transfers):
    """G8: legs leaving C (a ghost candidate) where C received none of those tokens in the same tx: the balance was
    there BEFORE the code (sent to a pre-computed address that had no code). Returns the kept legs."""
    inflow = {(t["tx"], t["to"], t["token"]) for t in transfers if t["value"] > 0}
    return [x for x in legs if (x["tx"], x["frm"], x["token"]) not in inflow]


# ---------- G11 legit-delegator decoy batch ----------
def decoy_batch(owner, transfers, routers):
    """G11: one self-call of a 7702-delegated EOA (tx.from == tx.to == owner) that moves the owner's ERC-20 tokens to
    other addresses AND touches a router (a decoy swap leg): tokens to / from a router in the same tx. Returns
    dict(recipients, legs) for non-router recipients, or None."""
    touched = any(t["to"] in routers or t["frm"] in routers for t in transfers)
    if not touched:
        return None
    outs = [t for t in transfers if t["frm"] == owner and t["value"] > 0 and t["to"] not in routers
            and t["to"] not in (owner, ZERO)]
    if not outs:
        return None
    return dict(recipients=sorted({t["to"] for t in outs}), legs=outs)
