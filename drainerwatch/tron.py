"""TRON: base58 addresses, TronGrid HTTP client (key rotation, credit-limit backoff), block / tx-info parsing.

Addresses are stored in base58check form (T...). TronGrid returns three spellings: base58 (`visible: true` block
data), 21-byte hex with the 0x41 prefix (tx-info `contract_address`, internal txs) and bare 20-byte hex (log address
and topics). Everything is normalised to base58 here so the chain-agnostic tables and the dashboard never see hex."""
import hashlib
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

from .util import HttpError, env, key_pool, redact

log = logging.getLogger("drainerwatch.tron")

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(B58)}
T_ADDR_RE = re.compile(r"^T[1-9A-HJ-NP-Za-km-z]{33}$")
TRON_API_DEFAULT = "https://api.trongrid.io"
KEY_HEADER = "TRON-PRO-API-KEY"


# ---------- addresses ----------
def _sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = len(b) - len(b.lstrip(b"\0"))
    return "1" * pad + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58_IDX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + body


def to_base58(h) -> str | None:
    """20-byte hex, 21-byte 0x41-prefixed hex (with or without 0x), or a 32-byte topic -> T... (None if malformed)."""
    if not h:
        return None
    if isinstance(h, str) and T_ADDR_RE.match(h):
        return h
    s = h[2:] if h.startswith("0x") else h
    s = s.lower()
    if len(s) == 64:
        s = s[-40:]
    if len(s) == 40:
        s = "41" + s
    if len(s) != 42 or not s.startswith("41"):
        return None
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        return None
    return b58encode(raw + _sha256d(raw)[:4])


def to_hex(addr: str) -> str | None:
    """T... -> '41' + 40 hex chars (None if the checksum fails)."""
    if not addr or not T_ADDR_RE.match(addr):
        return None
    raw = b58decode(addr)
    if len(raw) != 25 or _sha256d(raw[:21])[:4] != raw[21:]:
        return None
    return raw[:21].hex()


def is_tron_addr(a) -> bool:
    return bool(a) and to_hex(a) is not None


def word_addr(word: bytes | str) -> str:
    """ABI word (32 bytes or 64 hex chars) -> T... address."""
    if isinstance(word, (bytes, bytearray)):
        word = word.hex()
    return to_base58(word[-40:])


TRON_ZERO = to_base58("41" + "00" * 20)      # T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb: mint / burn / native placeholder


# ---------- client ----------
class TronRpc:
    """TronGrid full-node HTTP API. Keys: env TRONGRID_API_KEYS (comma list, header TRON-PRO-API-KEY, round robin; a key
    hit by the credit limit cools down for the suspension period). Keyless works at a lower rate: TronGrid allows
    ~300 credits/s per IP and suspends the IP for 5 s when exceeded, so the client spaces keyless calls and backs off."""
    chain = "tron"

    def __init__(self, url=None, workers=None):
        self.url = (url or env("TRON_API_URL", TRON_API_DEFAULT)).rstrip("/")
        self.pool = key_pool("TRONGRID_API_KEYS")
        self.keyless = len(self.pool) == 0
        self.workers = workers or (1 if self.keyless else min(3, len(self.pool)))
        self.interval = 0.35 if self.keyless else 0.0
        self.calls = 0
        self.limit_hits = 0
        self.errors = 0
        self.bytes = 0
        self._ts: dict[int, int] = {}
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "drainer-watch/0.1"
        self._lock = threading.Lock()
        self._last = 0.0
        self.last_size = None

    def _space(self):
        if self.interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._last + self.interval)
            self._last = slot
        if slot > now:
            time.sleep(slot - now)

    def post(self, path, body, retries=6, timeout=60):
        last = None
        for attempt in range(retries):
            self._space()
            key = self.pool.next()
            headers = {KEY_HEADER: key} if key else {}
            with self._lock:
                self.calls += 1
            try:
                r = self._session.post(self.url + path, json=body, headers=headers, timeout=timeout)
                if r.status_code in (403, 429) or "suspended" in r.text[:300]:
                    with self._lock:
                        self.limit_hits += 1
                    m = re.search(r"suspended for (\d+) s", r.text[:400])
                    wait = int(m.group(1)) if m else 5
                    if key:
                        self.pool.mark_bad(key, wait + 1)
                    last = f"HTTP {r.status_code} credit limit"
                    if self.keyless or len(self.pool) <= 1:
                        time.sleep(wait + 0.5)
                    continue
                if r.status_code >= 500:
                    last = f"HTTP {r.status_code}"
                elif r.status_code >= 400:
                    raise HttpError(f"HTTP {r.status_code} {path}: {redact(r.text[:200])}")
                else:
                    self.bytes += len(r.content)
                    return r.json()
            except (requests.RequestException, ValueError) as e:
                last = redact(repr(e))
            time.sleep(min(2 ** attempt, 20))
        with self._lock:
            self.errors += 1
        raise HttpError(f"tron {path}: retries exhausted ({last})")

    # ---- chain head / blocks ----
    def block_number(self):
        b = self.post("/wallet/getnowblock", {})
        return int(b["block_header"]["raw_data"]["number"])

    def blocks(self, a, b):
        """Full blocks a..b (inclusive) with base58 addresses, ordered by number. getblockbylimitnext takes at most 100
        blocks per call (endNum is exclusive)."""
        out = []
        n = a
        while n <= b:
            hi = min(b, n + 99)
            r = self.post("/wallet/getblockbylimitnext", {"startNum": n, "endNum": hi + 1, "visible": True})
            got = r.get("block") or []
            out += got
            n = hi + 1
        out.sort(key=lambda x: x["block_header"]["raw_data"].get("number", 0))
        for blk in out:
            hd = blk["block_header"]["raw_data"]
            self._ts[int(hd.get("number", 0))] = int(hd.get("timestamp", 0)) // 1000
        return out

    def tx_infos(self, numbers):
        """gettransactioninfobyblocknum for each block (parallel over the key pool) -> {block: [info] | None}."""
        def one(n):
            try:
                return n, self.post("/wallet/gettransactioninfobyblocknum", {"num": n}, retries=3 if self.keyless else 5)
            except HttpError as e:
                log.warning("tron: tx info of block %s unavailable (%s)", n, e)
                return n, None
        if self.workers <= 1:
            return dict(one(n) for n in numbers)
        with ThreadPoolExecutor(self.workers) as ex:
            return dict(ex.map(one, numbers))

    def block_times(self, numbers):
        need = [n for n in dict.fromkeys(numbers) if n and n not in self._ts]
        for n in need[:50]:
            try:
                b = self.post("/wallet/getblockbynum", {"num": n}, retries=3)
                self._ts[n] = int(b["block_header"]["raw_data"]["timestamp"]) // 1000
            except (HttpError, KeyError, TypeError):
                pass
        return {n: self._ts.get(n) for n in numbers}

    # ---- accounts / contracts ----
    def contract_info(self, addr):
        """-> dict(runtime=hex|'', origin=T...|None, name=str|None) for a contract, None for an account / unknown."""
        r = self.post("/wallet/getcontractinfo", {"value": addr, "visible": True}, retries=4)
        sc = (r or {}).get("smart_contract") or {}
        rt = (r or {}).get("runtimecode") or ""
        if not sc and not rt:
            return None
        return dict(runtime=rt, origin=to_base58(sc.get("origin_address")) if sc.get("origin_address") else None,
                    name=sc.get("name"))

    def get_code_many(self, addrs):
        """Same contract as Rpc.get_code_many: addr -> '0x<runtime>' for contracts, '0x' for accounts, None on error."""
        out = {}
        for a in addrs:
            if not is_tron_addr(a):
                continue
            try:
                ci = self.contract_info(a)
            except HttpError:
                out[a] = None
                continue
            out[a] = "0x" + ci["runtime"] if ci and ci["runtime"] else "0x"
            if ci:
                self.origins[a] = ci
        return out

    @property
    def origins(self):
        if not hasattr(self, "_origins"):
            self._origins = {}
        return self._origins

    def account(self, addr):
        try:
            return self.post("/wallet/getaccount", {"address": addr, "visible": True}, retries=4) or {}
        except HttpError:
            return None

    def eth_call_many(self, calls):
        """[(contract T..., '0x' calldata)] -> ['0x' result | None] via triggerconstantcontract (token metadata)."""
        out = []
        for to, data in calls:
            try:
                d = data[2:] if data.startswith("0x") else data
                r = self.post("/wallet/triggerconstantcontract", {"owner_address": TRON_ZERO, "contract_address": to,
                                                                  "function_selector": "", "data": d, "visible": True},
                              retries=3)
                res = (r.get("constant_result") or [None])[0]
                out.append("0x" + res if res else None)
            except HttpError:
                out.append(None)
        return out


# ---------- parsing ----------
TOPIC_TRANSFER_T = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
TOPIC_APPROVAL_T = "8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"


def parse_block(blk):
    """One `visible: true` block -> [tx] with: h, block, ts, idx, type, frm, to, ok, fee_limit, data (calldata hex, no
    0x), call_value, amount (TRX transfers, sun), perm (AccountPermissionUpdate payload), sig (signatures),
    raw_hex (for signer recovery)."""
    hd = blk["block_header"]["raw_data"]
    n, ts = int(hd.get("number", 0)), int(hd.get("timestamp", 0)) // 1000
    out = []
    for i, tx in enumerate(blk.get("transactions") or []):
        raw = tx.get("raw_data") or {}
        cs = raw.get("contract") or []
        if not cs:
            continue
        c = cs[0]
        v = (c.get("parameter") or {}).get("value") or {}
        ret = ((tx.get("ret") or [{}])[0] or {}).get("contractRet")
        d = dict(h=tx.get("txID"), block=n, ts=ts, idx=i, type=c.get("type"), frm=to_base58(v.get("owner_address")),
                 to=None, ok=ret in (None, "SUCCESS"), fee_limit=int(raw.get("fee_limit") or 0), data="",
                 call_value=0, amount=0, perm=None, sig=tx.get("signature") or [], perm_id=int(c.get("Permission_id") or 0))
        t = d["type"]
        if t == "TriggerSmartContract":
            d["to"] = to_base58(v.get("contract_address"))
            d["data"] = (v.get("data") or "").lower()
            d["call_value"] = int(v.get("call_value") or 0)
        elif t in ("TransferContract", "TransferAssetContract"):
            d["to"] = to_base58(v.get("to_address"))
            d["amount"] = int(v.get("amount") or 0)
            if t == "TransferAssetContract":
                d["asset"] = v.get("asset_name")
        elif t == "AccountPermissionUpdateContract":
            d["perm"] = dict(owner=v.get("owner") or {}, actives=v.get("actives") or [], witness=v.get("witness"))
            d["raw_hex"] = tx.get("raw_data_hex")
        if t != "AccountPermissionUpdateContract" and d["sig"]:
            d["raw_hex"] = tx.get("raw_data_hex")
        out.append(d)
    return out


def parse_infos(infos, block):
    """gettransactioninfobyblocknum result -> (transfers, approvals, meta). Transfer/Approval logs are returned in the
    EVM parse_logs shape with base58 addresses; meta = {txid: dict(fee, energy, result, created, internal)}. Internal
    TRX transfers (callValueInfo) are kept as (from, to, value) for the Claimer / fixed-fee rules."""
    tr, ap, meta = [], [], {}
    for x in infos or []:
        h = x.get("id")
        rc = x.get("receipt") or {}
        internal = []
        for it in x.get("internal_transactions") or []:
            for cv in it.get("callValueInfo") or []:
                val = int(cv.get("callValue") or 0)
                if val and not cv.get("tokenId") and not it.get("rejected"):
                    internal.append((to_base58(it.get("caller_address")), to_base58(it.get("transferTo_address")), val))
        meta[h] = dict(fee=int(x.get("fee") or 0), energy=int(rc.get("energy_usage_total") or 0),
                       result=rc.get("result"), created=to_base58(x.get("contract_address")) if x.get("contract_address") else None,
                       internal=internal)
        for li, lg in enumerate(x.get("log") or []):
            t = lg.get("topics") or []
            if len(t) != 3:
                continue
            token = to_base58(lg.get("address"))
            data = lg.get("data") or ""
            try:
                value = int(data[:64], 16) if data else 0
            except ValueError:
                continue
            base = dict(tx=h, li=li, block=block, token=token)
            if t[0] == TOPIC_TRANSFER_T:
                tr.append(dict(base, frm=word_addr(t[1]), to=word_addr(t[2]), value=value))
            elif t[0] == TOPIC_APPROVAL_T:
                ap.append(dict(base, owner=word_addr(t[1]), spender=word_addr(t[2]), value=value, kind="approval"))
    return tr, ap, meta


def signer_of(tx):
    """Base58 address that produced the first signature of a parsed tx (secp256k1 recovery over txID), or None."""
    from .auth7702 import pub_to_address, recover
    sig = (tx.get("sig") or [None])[0]
    if not sig or len(sig) != 130 or not tx.get("h"):
        return None
    try:
        r, s, v = int(sig[:64], 16), int(sig[64:128], 16), int(sig[128:], 16)
        q = recover(bytes.fromhex(tx["h"]), r, s, v - 27 if v >= 27 else v)
    except ValueError:
        return None
    return to_base58(pub_to_address(q)[2:]) if q else None
