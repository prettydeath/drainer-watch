"""JSON-RPC client: batching with id verification, adaptive eth_getLogs chunking."""
import logging
import time

from .constants import CHAINS, LOG_TOPICS
from .util import HttpError, env, http_json, hx

log = logging.getLogger("drainerwatch.rpc")

LIMIT_MARKERS = ("limit", "too many", "range", "exceed", "timeout", "timed out", "10000", "response size",
                 "query returned more", "block range", "too large", "resource", "capacity")


class RpcLimit(RuntimeError):
    """eth_getLogs refused or timed out: the caller must shrink the block range."""


class Rpc:
    def __init__(self, chain, url=None):
        cfg = CHAINS[chain]
        self.chain = chain
        self.url = url or env(cfg["rpc_env"], cfg["rpc"])
        self.calls = 0
        self.limit_hits = 0
        self.errors = 0
        self._ts: dict[int, int] = {}
        self.single_block = False
        self.last_size = None

    # ---- core ----
    def batch(self, calls, chunk=50, strict=True, retries=5):
        """calls: [(method, params)] -> [result]. strict=False: per-item errors become None."""
        out = []
        for i in range(0, len(calls), chunk):
            part = calls[i:i + chunk]
            payload = [{"jsonrpc": "2.0", "id": j, "method": m, "params": p} for j, (m, p) in enumerate(part)]
            self.calls += 1
            resp = http_json("POST", self.url, json=payload, interval=0.05, retries=retries,
                             validate=lambda o: isinstance(o, list) and len(o) == len(payload))
            by_id = {x.get("id"): x for x in resp}
            for j in range(len(part)):
                x = by_id.get(j)
                if x is None or "error" in x:
                    self.errors += 1
                    if strict:
                        raise HttpError(f"RPC error: {(x or {}).get('error')}")
                    out.append(None)
                else:
                    out.append(x["result"])
        return out

    def call(self, method, params, retries=5):
        self.calls += 1
        r = http_json("POST", self.url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
                      interval=0.05, retries=retries, validate=lambda o: isinstance(o, dict))
        if "error" in r:
            raise HttpError(f"RPC error: {r['error']}")
        return r["result"]

    # ---- helpers ----
    def block_number(self):
        return hx(self.call("eth_blockNumber", []))

    def get_code_many(self, addrs):
        res = self.batch([("eth_getCode", [a, "latest"]) for a in addrs], chunk=100, strict=False)
        return {a: r for a, r in zip(addrs, res)}

    def txs_by_hash(self, hashes):
        res = self.batch([("eth_getTransactionByHash", [h]) for h in hashes], chunk=50, strict=False)
        return {h: r for h, r in zip(hashes, res) if r}

    def receipts(self, hashes):
        res = self.batch([("eth_getTransactionReceipt", [h]) for h in hashes], chunk=50, strict=False)
        return {h: r for h, r in zip(hashes, res) if r}

    def nonces(self, addrs):
        res = self.batch([("eth_getTransactionCount", [a, "latest"]) for a in addrs], chunk=100, strict=False)
        return {a: (hx(r) if r is not None else None) for a, r in zip(addrs, res)}

    def balances(self, pairs):
        """pairs: [(addr, block)] -> {(addr, block): int|None} (eth_getBalance; historical blocks need an archive node,
        failures come back as None and the callers treat the check as unknown)."""
        res = self.batch([("eth_getBalance", [a, hex(b)]) for a, b in pairs], chunk=50, strict=False)
        return {p: (hx(r) if r is not None else None) for p, r in zip(pairs, res)}

    def storage_many(self, pairs):
        """pairs: [(addr, slot)] -> {(addr, slot): int|None} at latest."""
        res = self.batch([("eth_getStorageAt", [a, hex(s), "latest"]) for a, s in pairs], chunk=50, strict=False)
        return {p: (hx(r) if r is not None else None) for p, r in zip(pairs, res)}

    def eth_call_many(self, calls):
        """calls: [(to, data)] -> [hex|None]"""
        return self.batch([("eth_call", [{"to": t, "data": d}, "latest"]) for t, d in calls], chunk=50, strict=False)

    def block_times(self, numbers):
        need = [n for n in dict.fromkeys(numbers) if n not in self._ts]
        if need:
            res = self.batch([("eth_getBlockByNumber", [hex(n), False]) for n in need], chunk=50, strict=False)
            for n, r in zip(need, res):
                if r and r.get("timestamp"):
                    self._ts[n] = hx(r["timestamp"])
        return {n: self._ts.get(n) for n in numbers}

    def block_receipts(self, numbers, chunk=5):
        """eth_getBlockReceipts per block -> [list|None]. Served by publicnode even for historical blocks (archive
        getLogs is refused there), so it is the backtest source: logs + tx from/to/contractAddress, no tx lookups."""
        return self.batch([("eth_getBlockReceipts", [hex(n)]) for n in numbers], chunk=chunk, strict=False)

    def blocks_full(self, numbers, chunk=5):
        res = self.batch([("eth_getBlockByNumber", [hex(n), True]) for n in numbers], chunk=chunk, strict=False)
        for n, r in zip(numbers, res):
            if r and r.get("timestamp"):
                self._ts[n] = hx(r["timestamp"])
        return res

    # ---- logs ----
    def get_logs(self, a, b, topics=None):
        """eth_getLogs over [a, b]. Public nodes (publicnode since 2026-11) refuse address-less multi-block queries
        ("Please specify an address"); the client then switches to one getLogs per block inside JSON-RPC batches."""
        if self.single_block and b > a:
            return self._get_logs_per_block(a, b, topics)
        params = [{"fromBlock": hex(a), "toBlock": hex(b), "topics": [topics or LOG_TOPICS]}]
        self.calls += 1
        try:
            r = http_json("POST", self.url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_getLogs", "params": params},
                          interval=0.05, retries=3, timeout=60, validate=lambda o: isinstance(o, dict))
        except HttpError as e:  # timeouts / 5xx after retries: treat as "too heavy"
            raise RpcLimit(str(e)) from e
        if "error" in r:
            msg = str(r["error"]).lower()
            if "specify an address" in msg and b > a:
                log.info("%s: node refuses multi-block address-less getLogs; switching to per-block batches", self.chain)
                self.single_block = True
                return self._get_logs_per_block(a, b, topics)
            if any(m in msg for m in LIMIT_MARKERS):
                raise RpcLimit(msg[:200])
            raise HttpError(f"RPC error: {r['error']}")
        return r["result"]

    def _get_logs_per_block(self, a, b, topics=None):
        t = [topics or LOG_TOPICS]
        calls = [("eth_getLogs", [{"fromBlock": hex(n), "toBlock": hex(n), "topics": t}]) for n in range(a, b + 1)]
        try:
            res = self.batch(calls, chunk=25, strict=False, retries=3)
        except HttpError as e:
            raise RpcLimit(str(e)) from e
        if any(r is None for r in res):
            raise RpcLimit("per-block getLogs item failed")
        return [lg for r in res for lg in r]

    def iter_logs(self, a, b, deadline, size, max_size=400, heavy=6000):
        """Yield (from, to, logs) over [a, b] with adaptive chunk size (halve on limit, grow on light chunks).
        Stops when `deadline` (monotonic) passes; the caller reads the last yielded `to` to advance its cursor."""
        while a <= b and time.monotonic() < deadline:
            hi = min(b, a + size - 1)
            try:
                logs = self.get_logs(a, hi)
            except RpcLimit as e:
                self.limit_hits += 1
                if hi == a:
                    log.warning("%s: single-block getLogs refused at %s (%s); skipping block", self.chain, a, e)
                    yield a, a, []
                    a += 1
                    continue
                size = max(1, size // 2)
                log.info("%s: getLogs limit at %s-%s, chunk -> %s", self.chain, a, hi, size)
                continue
            self.last_size = size
            yield a, hi, logs
            a = hi + 1
            if len(logs) > heavy:
                size = max(1, size // 2)
            elif len(logs) < heavy // 4:
                size = min(max_size if not self.single_block else 100, size * 2)
        self.last_size = size


    # ---- receipts ----
    def iter_receipts(self, a, b, deadline, size=10):
        """Yield (from, to, logs, txmeta) per chunk of blocks using eth_getBlockReceipts. logs = Transfer/Approval/
        ApprovalForAll logs in eth_getLogs shape; txmeta = {tx_hash: {from, to, block, created, status}} for EVERY tx
        in the block, so detectors never need eth_getTransactionByHash. A block whose receipts cannot be fetched after
        a single retry is skipped with a warning (counted in errors), like a refused single-block getLogs."""
        while a <= b and time.monotonic() < deadline:
            hi = min(b, a + size - 1)
            nums = list(range(a, hi + 1))
            try:
                res = self.block_receipts(nums)
            except HttpError as e:
                log.warning("%s: getBlockReceipts %s-%s failed (%s); retrying per block", self.chain, a, hi, e)
                res = [None] * len(nums)
            logs, meta = [], {}
            for n, r in zip(nums, res):
                if r is None:
                    try:
                        r = self.call("eth_getBlockReceipts", [hex(n)], retries=3)
                    except HttpError as e:
                        self.errors += 1
                        log.warning("%s: receipts for block %s unavailable (%s); skipping block", self.chain, n, e)
                        continue
                lg, mt = split_receipts(r or [])
                logs += lg
                meta.update(mt)
            yield a, hi, logs, meta
            a = hi + 1


def split_receipts(receipts):
    """Block receipts -> (logs filtered to LOG_TOPICS, txmeta)."""
    topics = set(LOG_TOPICS)
    logs, meta = [], {}
    for rc in receipts:
        h = rc["transactionHash"]
        meta[h] = {"from": (rc.get("from") or "").lower(), "to": (rc.get("to") or "").lower() or None,
                   "block": hx(rc.get("blockNumber")), "created": (rc.get("contractAddress") or "").lower() or None,
                   "status": hx(rc.get("status"), 1)}
        for lg in rc.get("logs") or []:
            t = lg.get("topics") or []
            if t and t[0] in topics and not lg.get("removed"):
                logs.append(lg)
    return logs, meta


def parse_logs(logs):
    """Raw eth_getLogs -> (transfers, approvals). ERC-721 Transfer (4 topics) is ignored in the MVP;
    ApprovalForAll is returned as an approval with kind='all'."""
    from .constants import TOPIC_APPROVAL, TOPIC_APPROVAL_ALL, TOPIC_TRANSFER
    from .util import addr_of_topic
    tr, ap = [], []
    for lg in logs:
        t = lg.get("topics") or []
        if not t:
            continue
        t0 = t[0]
        base = dict(tx=lg["transactionHash"], li=hx(lg.get("logIndex")), block=hx(lg.get("blockNumber")),
                    token=lg["address"].lower())
        if t0 == TOPIC_TRANSFER and len(t) == 3:
            tr.append(dict(base, frm=addr_of_topic(t[1]), to=addr_of_topic(t[2]), value=hx(lg.get("data"))))
        elif t0 == TOPIC_APPROVAL and len(t) == 3:
            ap.append(dict(base, owner=addr_of_topic(t[1]), spender=addr_of_topic(t[2]), value=hx(lg.get("data")),
                           kind="approval"))
        elif t0 == TOPIC_APPROVAL_ALL and len(t) == 3:
            ap.append(dict(base, owner=addr_of_topic(t[1]), spender=addr_of_topic(t[2]),
                           value=hx(lg.get("data")), kind="all"))
    return tr, ap
