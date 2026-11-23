"""HTTP with retries, keccak, key rotation, time. Secrets (API keys in query strings) are redacted from every message."""
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone

import requests
from Crypto.Hash import keccak as _keccak

log = logging.getLogger("drainerwatch")

_last_call: dict[str, float] = {}
_session = requests.Session()
_session.headers["User-Agent"] = "drainer-watch/0.1"
_lock = threading.Lock()

_SECRET_RE = re.compile(r"(apikey|api_key|token|key)=[^&\s'\"]+", re.I)


class HttpError(RuntimeError):
    pass


def redact(s) -> str:
    return _SECRET_RE.sub(lambda m: m.group(1) + "=***", str(s))


def throttle(key: str, interval: float) -> None:
    if interval <= 0:
        return
    with _lock:
        now = time.monotonic()
        slot = max(now, _last_call.get(key, 0) + interval)
        _last_call[key] = slot
    if slot > now:
        time.sleep(slot - now)


def http_json(method, url, *, interval=0.0, retries=6, timeout=40, validate=None, **kw):
    """JSON request with exponential backoff. validate(obj)->bool; False => retry."""
    host = url.split("/")[2]
    last = None
    for attempt in range(retries):
        throttle(host, interval)
        try:
            r = _session.request(method, url, timeout=timeout, **kw)
            if r.status_code in (429, 500, 502, 503, 504, 522, 524):
                last = f"HTTP {r.status_code}"
            elif r.status_code >= 400:
                raise HttpError(f"HTTP {r.status_code} {url}: {redact(r.text[:200])}")
            else:
                obj = r.json()
                if validate is None or validate(obj):
                    return obj
                last = f"invalid response: {redact(str(obj)[:150])}"
        except (requests.RequestException, ValueError) as e:
            last = redact(repr(e))
        if attempt == retries - 1:
            break
        delay = min(2 ** attempt, 30)
        log.debug("retry %s (%s) in %ss", host, last, delay)
        time.sleep(delay)
    raise HttpError(f"{url}: retries exhausted ({last})")


def http_text(url, *, timeout=60, retries=3):
    last = None
    for attempt in range(retries):
        try:
            r = _session.get(url, timeout=timeout)
            if r.status_code == 200:
                return r.text
            last = f"HTTP {r.status_code}"
        except requests.RequestException as e:
            last = redact(repr(e))
        if attempt < retries - 1:
            time.sleep(2 ** attempt)
    raise HttpError(f"{url}: {last}")


# ---------- keccak / hex ----------
def keccak(b: bytes) -> bytes:
    return _keccak.new(digest_bits=256, data=b).digest()


def topic(sig: str) -> str:
    return "0x" + keccak(sig.encode()).hex()


def selector(sig: str) -> str:
    return keccak(sig.encode())[:4].hex()


def hx(v, default=0) -> int:
    if v is None:
        return default
    if isinstance(v, int):
        return v
    return int(v, 16) if v not in ("", "0x") else default


def addr_of_topic(t: str) -> str:
    return "0x" + t[-40:].lower()


def norm_addr(a):
    if not a:
        return None
    a = str(a).strip().lower()
    if re.fullmatch(r"0x[0-9a-f]{40}", a):
        return a
    return None


# ---------- time ----------
def iso(ts):
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    if not s:
        return None
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def now_ts() -> int:
    return int(time.time())


def env(name: str, default=None):
    v = os.environ.get(name)
    return v if v else default


def load_env_file(path, names=None) -> list:
    """KEY=VALUE lines -> os.environ (process only; existing values win). Returns the loaded NAMES, never values."""
    loaded = []
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return loaded
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k.startswith("export "):
            k = k[7:].strip()
        if not k or not v or (names and k not in names) or os.environ.get(k):
            continue
        os.environ[k] = v
        loaded.append(k)
    return loaded


# ---------- API key rotation ----------
class KeyPool:
    """Round-robin over comma-separated API keys with per-key cooldown. Key values are never logged."""

    def __init__(self, raw, cooldown=60.0, clock=time.monotonic):
        self.keys = [k.strip() for k in re.split(r"[,;\r\n]+", raw or "") if k.strip()]
        self.cooldown = cooldown
        self.clock = clock
        self._i = 0
        self._until = {}
        self._lock = threading.Lock()

    def __len__(self):
        return len(self.keys)

    def next(self):
        if not self.keys:
            return None
        with self._lock:
            now = self.clock()
            n = len(self.keys)
            for step in range(n):
                idx = (self._i + step) % n
                if self._until.get(idx, 0) <= now:
                    self._i = (idx + 1) % n
                    return self.keys[idx]
            idx = min(range(n), key=lambda j: self._until.get(j, 0))
            self._i = (idx + 1) % n
            return self.keys[idx]

    def mark_bad(self, key, seconds=None):
        if key in self.keys:
            with self._lock:
                self._until[self.keys.index(key)] = self.clock() + (seconds or self.cooldown)


_pools = {}


def key_pool(name):
    raw = os.environ.get(name, "")
    p = _pools.get(name)
    if p is None or p[0] != raw:
        p = (raw, KeyPool(raw))
        _pools[name] = p
    return p[1]


RATE_LIMIT_MARKERS = ("rate limit", "max calls", "invalid api key", "api key", "too many", "429", "suspended")


def looks_rate_limited(obj) -> bool:
    s = str(obj).lower()
    return any(m in s for m in RATE_LIMIT_MARKERS)
