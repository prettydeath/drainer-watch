"""Ground-truth incident set for the blind backtest.

Seeds = ScamSniffer blacklist + wallet-attribution `scam` labels that name phishing/drainers (Forta `Fake_Phishing*`,
"phishing", "drainer"). For each seed (deterministic order) Etherscan `tokentx` / `txlist` (ETH, 2025+) gives candidate
txs; every candidate is re-checked against its real receipt and kept only if it shows a PULL: an ERC-20 Transfer whose
`from` (the victim, an EOA) is neither tx.from nor tx.to, and the seed is the recipient, tx.to or tx.from of that tx.
Native value sent to a seed contract through a method call (victim-signed payable 'Claim') is kept as pattern
`native_payable`. Nothing is inferred beyond what the receipt shows.

Split: incidents are grouped into components (seed + pull actor `drainer`, union-find) so one drainer never lands in
both splits; component -> dev if sha256(min address) % 10 < 6, else holdout."""
import csv
import hashlib
import logging
import time
from collections import defaultdict

from . import seeds as seedmod
from .bytecode import is_delegated_eoa
from .constants import ALLOWLIST, TOPIC_TRANSFER, ZERO
from .enrich import Etherscan
from .rpc import Rpc
from .tokens import Tokens
from .util import addr_of_topic, hx, iso, norm_addr

log = logging.getLogger("drainerwatch.incidents")

START_BLOCK_2025 = 21_525_000          # ~2025-01-01
FIELDS = ["split", "chain", "block", "ts", "tx", "seed_address", "role_of_seed", "token", "symbol", "victim",
          "tx_from", "tx_to", "drainer", "pattern", "seed_source", "note"]
WA_KEYWORDS = ("fake_phishing", "phish", "drainer")


def wa_seed_rows(path):
    """wallet-attribution ethereum.csv -> [(address, label)] for scam labels that name phishing / drainers."""
    out = []
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            if (r.get("category") or "").strip().lower() != "scam":
                continue
            lb = (r.get("label") or "")
            if any(k in lb.lower() for k in WA_KEYWORDS):
                a = norm_addr(r.get("address"))
                if a:
                    out.append((a, lb.strip()))
    return out


def seed_order(addrs):
    return sorted(set(addrs), key=lambda a: hashlib.sha256(a.encode()).hexdigest())


def spread(items, k):
    """Pick k items evenly over a sorted list (time diversity, deterministic)."""
    if len(items) <= k:
        return list(items)
    step = (len(items) - 1) / (k - 1) if k > 1 else 0
    return [items[round(i * step)] for i in range(k)]


def transfers_of(receipt):
    out = []
    for lg in receipt.get("logs") or []:
        t = lg.get("topics") or []
        if len(t) == 3 and t[0] == TOPIC_TRANSFER:
            out.append(dict(token=lg["address"].lower(), frm=addr_of_topic(t[1]), to=addr_of_topic(t[2]),
                            value=hx(lg.get("data")), li=hx(lg.get("logIndex"))))
    return out


def classify(receipt, seed, is_eoa, is_spoof):
    """Receipt -> list of pull legs that involve `seed` (dicts) or []. Pure function (testable)."""
    if hx(receipt.get("status"), 1) != 1:
        return []
    frm = (receipt.get("from") or "").lower()
    to = (receipt.get("to") or "").lower()
    out = []
    for t in transfers_of(receipt):
        v = t["frm"]
        if t["value"] == 0 or v in (frm, to, ZERO, seed) or int(v, 16) <= 0xFFFF:
            continue
        if not (t["to"] == seed or to == seed or frm == seed):
            continue
        if not is_eoa(v) or is_spoof(t["token"]):
            continue
        role = "drainer_contract" if to == seed else ("operator" if frm == seed else "payout")
        if to == t["token"]:
            pattern = "eoa_transferFrom"
        elif to in ALLOWLIST:
            pattern = "via_allowlisted:" + ALLOWLIST[to]
        else:
            pattern = "pull_via_contract"
        out.append(dict(t, role=role, pattern=pattern, tx_from=frm, tx_to=to))
    return out


def set_actor(rows):
    """`drainer` = the address that executed the pull: tx.to for a contract pull (already set), tx.from when the pull
    went straight through the token (EOA spender calling transferFrom) or through an allowlisted contract (Permit2,
    Seaport: the operator EOA submits the victim's signature). Used for scoring and for the component split."""
    for r in rows:
        if not r["drainer"] and (r["pattern"] == "eoa_transferFrom" or r["pattern"].startswith("via_allowlisted")):
            r["drainer"] = r["tx_from"]
    return rows


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
        self.p[self.find(a)] = self.find(b)


def assign_splits(rows, dev_pct=6):
    uf = UF()
    for r in rows:
        uf.find(r["seed_address"])
        if r["drainer"]:
            uf.union(r["seed_address"], r["drainer"])
    comp = defaultdict(list)
    for r in rows:
        comp[uf.find(r["seed_address"])].append(r)
    for members in comp.values():
        key = min({m["seed_address"] for m in members} | {m["drainer"] for m in members if m["drainer"]})
        sp = "dev" if int(hashlib.sha256(key.encode()).hexdigest(), 16) % 10 < dev_pct else "holdout"
        for m in members:
            m["split"] = sp
    return rows


def build(conn, out_path, wa_path=None, target_seeds=60, per_seed=4, max_seeds_scanned=1500, budget_sec=3600):
    t0 = time.monotonic()
    es = Etherscan(calls_cap=10_000)
    if not es.enabled:
        raise SystemExit("ETHERSCAN_API_KEYS is not set")
    rpc = Rpc("eth")
    tokens = Tokens(conn, rpc, "eth")
    ss = seedmod.fetch_scamsniffer()
    src = {a: "scamsniffer" for a in ss}
    if wa_path:
        for a, lb in wa_seed_rows(wa_path):
            src.setdefault(a, "wallet-attribution:" + lb)
    order = seed_order(src)
    log.info("incident seeds: %d (scamsniffer %d)", len(order), len(ss))
    code_cache = {}

    def is_eoa_many(addrs):
        need = [a for a in set(addrs) if a not in code_cache]
        if need:
            for a, c in rpc.get_code_many(need).items():
                code_cache[a] = c
        return {a: (code_cache.get(a) in ("0x", None) or is_delegated_eoa(code_cache.get(a))) for a in addrs}

    rows, seeds_hit, scanned = [], 0, 0
    for seed in order:
        if seeds_hit >= target_seeds or scanned >= max_seeds_scanned or time.monotonic() - t0 > budget_sec:
            break
        scanned += 1
        base = dict(address=seed, startblock=START_BLOCK_2025, endblock=99_999_999, page=1, offset=100, sort="desc")
        tt = es.call("eth", dict(base, module="account", action="tokentx")) or []
        tl = es.call("eth", dict(base, module="account", action="txlist")) or []
        cand = {}
        for r in tt:
            if (r.get("to") or "").lower() == seed and (r.get("from") or "").lower() not in (seed, ZERO) \
                    and int(r.get("value") or 0) > 0:
                cand[r["hash"].lower()] = int(r["blockNumber"])
        native = []
        for r in tl:
            if r.get("isError") != "0":
                continue
            h = r["hash"].lower()
            if (r.get("to") or "").lower() == seed or (r.get("from") or "").lower() == seed:
                cand[h] = int(r["blockNumber"])
            if (r.get("to") or "").lower() == seed and int(r.get("value") or 0) > 0 and len(r.get("input") or "") >= 10:
                native.append(r)
        if not cand and not native:
            continue
        hashes = [h for h, _ in sorted(cand.items(), key=lambda kv: kv[1])]
        hashes = spread(hashes, 16)
        rc = rpc.receipts(hashes)
        legs_by_tx = {}
        victims = {t["frm"] for r in rc.values() for t in transfers_of(r)}
        eoa = is_eoa_many(list(victims) + [seed]) if victims else is_eoa_many([seed])
        all_tok = {t["token"] for r in rc.values() for t in transfers_of(r)}
        tokens.ensure(all_tok)
        for h, r in rc.items():
            legs = classify(r, seed, lambda a: eoa.get(a, False), tokens.is_spoof)
            if legs:
                legs_by_tx[h] = (r, legs)
        found = []
        is_eoa_many([x["tx_to"] for _, legs in legs_by_tx.values() for x in legs if x["tx_to"]])
        for h, (r, legs) in legs_by_tx.items():
            lg = max(legs, key=lambda x: x["value"])
            sym, _ = tokens.get(lg["token"])
            c = code_cache.get(lg["tx_to"])
            drainer = lg["tx_to"] if lg["pattern"] == "pull_via_contract" and c not in ("0x", None) and not is_delegated_eoa(c) else ""
            nv = len({x["frm"] for x in legs})
            rec = {x["to"] for x in legs if x["token"] == lg["token"] and x["frm"] == lg["frm"]}
            found.append(dict(chain="eth", block=hx(r["blockNumber"]), tx=h, seed_address=seed, role_of_seed=lg["role"],
                              token=lg["token"], symbol=sym or "", victim=lg["frm"], tx_from=lg["tx_from"],
                              tx_to=lg["tx_to"], drainer=drainer, pattern=lg["pattern"], seed_source=src[seed],
                              note=f"pull legs {len(legs)}, victims {nv}, recipients of top leg {len(rec)}"))
        if not code_cache.get(seed) in ("0x", None) and not is_delegated_eoa(code_cache.get(seed)):
            for r in native:
                h = r["hash"].lower()
                if any(f["tx"] == h for f in found):
                    continue
                found.append(dict(chain="eth", block=int(r["blockNumber"]), tx=h, seed_address=seed,
                                  role_of_seed="drainer_contract", token="native", symbol="ETH",
                                  victim=(r.get("from") or "").lower(), tx_from=(r.get("from") or "").lower(),
                                  tx_to=seed, drainer=seed, pattern="native_payable", seed_source=src[seed],
                                  note=f"value {int(r['value']) / 1e18:.6f} ETH, method {r.get('functionName') or r['input'][:10]}"))
        if not found:
            continue
        found.sort(key=lambda f: f["block"])
        found = spread(found, per_seed)
        seeds_hit += 1
        rows += found
        log.info("seed %d/%d %s: %d incidents (patterns %s)", seeds_hit, scanned, seed, len(found),
                 sorted({f["pattern"] for f in found}))
    # timestamps for the report
    bts = rpc.block_times(sorted({r["block"] for r in rows}))
    for r in rows:
        r["ts"] = iso(bts.get(r["block"]))
    set_actor(rows)
    assign_splits(rows)
    rows.sort(key=lambda r: (r["split"], r["seed_address"], r["block"]))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})
    log.info("incidents: %d rows, %d seeds with incidents, %d seeds scanned, etherscan calls %d", len(rows), seeds_hit,
             scanned, es.calls)
    return rows


def load(path, split=None):
    with open(path, newline="", encoding="utf-8") as f:
        rows = [dict(r, block=int(r["block"])) for r in csv.DictReader(f)]
    return [r for r in rows if split in (None, "all") or r["split"] == split]


def refinalize(path):
    """Re-apply set_actor + split to an existing csv (deterministic; used after editing the rules above)."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    set_actor(rows)
    assign_splits(rows)
    rows.sort(key=lambda r: (r["split"], r["seed_address"], int(r["block"])))
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})
    return rows
