"""Per-wallet aggregate for the dashboard's wallet case file (`wallets` in data.json).

Covers addresses that hold freezable stablecoins, payout wallets of T1/T2 subjects and the top operator wallets, in that
priority, capped at MAX_WALLETS. Inflows come from the full drains table (drains.recipient), not the capped `drains`
list; outflows are the known exchange links (vasp_links) with the wallet as subject."""
from collections import defaultdict

from .util import iso

MAX_WALLETS = 400
MAX_INFLOWS = 50
MAX_OUTFLOWS = 50


def _num(x):
    return round(float(x), 2) if x is not None else None


def payload(conn, contracts, freezable, operators, limit=MAX_WALLETS, per=MAX_INFLOWS):
    """{"chain:address": {roles, drainers, inflows, outflows_known, first_in, last_in, total_in_usd, n_in}}."""
    tier = {(c["chain"], c["address"]): c["tier"] for c in contracts}
    order, roles = [], defaultdict(set)

    def want(ch, w, role=None):
        if not w:
            return
        k = (ch, w)
        if k not in roles:
            order.append(k)
        roles[k]                              # registers the key
        if role:
            roles[k].add(role)

    for f in freezable or []:
        want(f["chain"], f["address"], f.get("role"))
    strong = sorted((c for c in contracts if c["tier"] in ("T1", "T2")), key=lambda c: -(c.get("usd") or 0))
    for c in strong:
        for p in c.get("payouts") or []:
            want(c["chain"], p["wallet"], p.get("role"))
    for o in operators or []:
        want(o["chain"], o["wallet"])
    keys = set(order[:limit])
    if not keys:
        return {}

    # every payout link of the chosen wallets, whatever the subject's tier
    links = defaultdict(dict)
    for r in conn.execute("SELECT chain,drainer,wallet,role,share,txs FROM payouts"):
        k = (r["chain"], r["wallet"])
        if k in keys:
            if r["role"]:
                roles[k].add(r["role"])
            links[k][r["drainer"]] = dict(drainer=r["drainer"], tier=tier.get((r["chain"], r["drainer"])), role=r["role"],
                                          share=_num(r["share"]), usd=0.0, txs=0, first=None, last=None)

    agg = defaultdict(lambda: dict(n=0, usd=0.0, first=None, last=None, rows=[]))
    wallets = {w for _, w in keys}
    for r in conn.execute("SELECT chain,tx,ts,victim,drainer,token,symbol,amount,usd,recipient FROM drains "
                          "WHERE recipient IS NOT NULL ORDER BY ts DESC, tx DESC"):
        if r["recipient"] not in wallets:
            continue
        k = (r["chain"], r["recipient"])
        if k not in keys:
            continue
        g = agg[k]
        g["n"] += 1
        g["usd"] += r["usd"] or 0
        ts = r["ts"]
        if ts is not None:
            g["last"] = ts if g["last"] is None else max(g["last"], ts)
            g["first"] = ts if g["first"] is None else min(g["first"], ts)
        if len(g["rows"]) < per:
            g["rows"].append(dict(tx=r["tx"], ts=iso(ts) or "", victim=r["victim"], drainer=r["drainer"], token=r["token"],
                                  symbol=r["symbol"], amount=r["amount"], usd=_num(r["usd"])))
        d = links[k].get(r["drainer"])
        if d is None:
            d = links[k][r["drainer"]] = dict(drainer=r["drainer"], tier=tier.get((r["chain"], r["drainer"])), role=None,
                                              share=None, usd=0.0, txs=0, first=None, last=None)
        d["usd"] += r["usd"] or 0
        d["txs"] += 1
        if ts is not None:
            d["first"] = ts if d["first"] is None else min(d["first"], ts)
            d["last"] = ts if d["last"] is None else max(d["last"], ts)

    out_links = defaultdict(list)
    for r in conn.execute("SELECT * FROM vasp_links ORDER BY ts DESC"):
        k = (r["chain"], r["subject"])
        if k in keys and len(out_links[k]) < MAX_OUTFLOWS:
            out_links[k].append(dict(counterparty=r["counterparty"], kind=r["kind"], entity=r["entity"],
                                     category=r["category"], tx=r["tx"], tx_in=r["tx_in"], ts=iso(r["ts"]) or "",
                                     amount=r["amount"], symbol=r["symbol"], usd=_num(r["usd"]),
                                     confidence=r["confidence"]))

    out = {}
    for k in order[:limit]:
        g = agg.get(k)
        ds = sorted(links[k].values(), key=lambda d: (-d["usd"], -(d["txs"] or 0)))
        for d in ds:
            d["usd"] = round(d["usd"], 2)
            d["first"], d["last"] = iso(d["first"]) or None, iso(d["last"]) or None
        out[k[0] + ":" + k[1]] = dict(
            roles=sorted(x for x in roles[k] if x), drainers=ds, inflows=g["rows"] if g else [],
            outflows_known=out_links.get(k, []), first_in=iso(g["first"]) if g and g["first"] else None,
            last_in=iso(g["last"]) if g and g["last"] else None, total_in_usd=round(g["usd"], 2) if g else 0.0,
            n_in=g["n"] if g else 0)
    return out
