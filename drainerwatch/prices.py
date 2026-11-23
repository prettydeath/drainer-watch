"""USD prices: CoinGecko simple price for ETH/BNB (keyless); stablecoins = 1.0 by address. Unknown tokens: None."""
import logging

from .constants import CHAINS, COINGECKO, STABLES, WRAPPED_NATIVE
from .db import meta_get, meta_set
from .util import http_json, now_ts

log = logging.getLogger("drainerwatch.prices")
IDS = {"ETH": "ethereum", "BNB": "binancecoin"}
REFRESH_SEC = 600


class Prices:
    def __init__(self, conn=None, native=None):
        self.conn = conn
        self.native = dict(native or {})      # {"ETH": 3000.0, "BNB": 600.0}
        if conn is not None and not native:
            for sym, cid in IDS.items():
                v = meta_get(conn, f"price:{cid}")
                if v:
                    self.native[sym] = float(v)

    def refresh(self):
        if self.conn is not None and now_ts() - int(meta_get(self.conn, "price_at", "0") or 0) < REFRESH_SEC and self.native:
            return
        try:
            r = http_json("GET", COINGECKO, params={"ids": ",".join(IDS.values()), "vs_currencies": "usd"},
                          retries=3, timeout=20, validate=lambda o: isinstance(o, dict) and "ethereum" in o)
            for sym, cid in IDS.items():
                p = (r.get(cid) or {}).get("usd")
                if p:
                    self.native[sym] = float(p)
                    if self.conn is not None:
                        meta_set(self.conn, f"price:{cid}", p)
            if self.conn is not None:
                meta_set(self.conn, "price_at", now_ts())
        except Exception as e:  # noqa: BLE001
            log.warning("prices: CoinGecko unavailable (%s); using cached %s", e, sorted(self.native))

    def unit_price(self, chain, token):
        if token in STABLES.get(chain, ()):
            return 1.0
        sym = WRAPPED_NATIVE.get(chain, {}).get(token)
        if sym:
            return self.native.get(sym)
        return None

    def usd(self, chain, token, raw, decimals):
        p = self.unit_price(chain, token)
        if p is None or decimals is None:
            return None
        return round(raw / 10 ** decimals * p, 2)
