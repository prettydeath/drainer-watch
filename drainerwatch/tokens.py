"""ERC-20 symbol/decimals via eth_call, cached in the `tokens` table."""
import logging
from decimal import Decimal

from .constants import SEL_DECIMALS, SEL_SYMBOL

log = logging.getLogger("drainerwatch.tokens")


def decode_symbol(h):
    if not h or h == "0x":
        return None
    try:
        raw = bytes.fromhex(h[2:])
    except ValueError:
        return None
    try:
        if len(raw) >= 96:
            off = int.from_bytes(raw[:32], "big")
            if off + 32 <= len(raw):
                ln = int.from_bytes(raw[off:off + 32], "big")
                if 0 < ln <= 64 and off + 32 + ln <= len(raw):
                    return raw[off + 32:off + 32 + ln].decode("utf-8", "replace").strip("\x00")[:24] or None
        if len(raw) == 32:
            return raw.rstrip(b"\x00").decode("utf-8", "replace")[:24] or None
    except (ValueError, OverflowError):
        return None
    return None


def decode_decimals(h):
    if not h or h == "0x" or len(h) < 4:
        return None
    try:
        v = int(h, 16)
    except ValueError:
        return None
    return v if 0 <= v <= 77 else None


def fmt_amount(raw, decimals):
    """Exact decimal string; raw integer string if decimals unknown."""
    if decimals is None:
        return str(raw)
    d = Decimal(raw).scaleb(-decimals)
    s = format(d, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s or "0"


CANON_SYMBOLS = ("USDT", "USDC", "DAI", "ETH", "WETH", "BNB", "WBNB", "BUSD", "USDE", "FDUSD", "USDS", "PYUSD", "WBTC",
                 "BTCB", "USD1", "TUSD")


def _lev1(a, b):
    """True if Levenshtein distance(a, b) <= 1."""
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) <= 1
    if len(a) > len(b):
        a, b = b, a
    for i in range(len(b)):
        if b[:i] + b[i + 1:] == a:
            return True
    return False


def is_spoof_symbol(symbol, canonical_token):
    """Fake-token heuristic (address poisoning): a symbol with non-ASCII / invisible characters, or a symbol within one
    edit of a major stablecoin/native symbol on a token that is NOT the canonical contract. Such Transfer events are
    emitted by the attacker's own token, nothing is pulled from the 'victim' (address-poisoning, not a drain)."""
    if not symbol:
        return False
    if not symbol.isascii() or not symbol.isprintable():
        return True
    if canonical_token:
        return False
    s = symbol.upper().strip()
    return any(_lev1(s, c) for c in CANON_SYMBOLS)


class Tokens:
    def __init__(self, conn, rpc, chain):
        self.conn, self.rpc, self.chain = conn, rpc, chain
        self.cache = {}
        for r in conn.execute("SELECT address,symbol,decimals FROM tokens WHERE chain=?", (chain,)):
            self.cache[r["address"]] = (r["symbol"], r["decimals"])

    def ensure(self, addrs):
        need = [a for a in dict.fromkeys(addrs) if a not in self.cache]
        if not need:
            return
        calls = []
        for a in need:
            calls += [(a, SEL_SYMBOL), (a, SEL_DECIMALS)]
        try:
            res = self.rpc.eth_call_many(calls)
        except Exception as e:  # noqa: BLE001
            log.warning("token metadata lookup failed: %s", e)
            return
        for i, a in enumerate(need):
            sym, dec = decode_symbol(res[2 * i]), decode_decimals(res[2 * i + 1])
            self.cache[a] = (sym, dec)
            self.conn.execute("INSERT OR REPLACE INTO tokens(chain,address,symbol,decimals) VALUES(?,?,?,?)",
                              (self.chain, a, sym, dec))

    def get(self, addr):
        return self.cache.get(addr, (None, None))

    def is_spoof(self, addr):
        from .constants import STABLES, WRAPPED_NATIVE
        canon = addr in STABLES.get(self.chain, ()) or addr in WRAPPED_NATIVE.get(self.chain, {})
        return is_spoof_symbol(self.get(addr)[0], canon)
