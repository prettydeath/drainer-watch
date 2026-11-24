"""Freezable stablecoin balances: targets, batched calls through a fake RPC, cache, payload and totals."""
import json

from drainerwatch import freeze
from drainerwatch.render import build_payload
from tests.helpers import a, make_ctx

USDT, USDC = "0xdac17f958d2ee523a2206206994597c13d831ec7", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"


class CallRpc:
    def __init__(self, bal, frozen=()):
        self.bal, self.frozen, self.calls = bal, set(frozen), []

    def eth_call_many(self, calls):
        self.calls.append(len(calls))
        out = []
        for to, data in calls:
            addr = "0x" + data[-40:]
            if data[2:10] == freeze.SEL_BALANCE:
                out.append("0x" + f"{self.bal.get((to, addr), 0):064x}")
            else:
                out.append("0x" + f"{int((to, addr) in self.frozen):064x}")
        return out


def _db():
    c = make_ctx().conn
    d, d3, op, aff = a(0xD1), a(0xD3), a(0x0F), a(0xAF)
    for addr, tier in ((d, "T1"), (d3, "T3")):
        c.execute("INSERT INTO contracts(chain,address,tier,score,source,labels,last_seen) VALUES('eth',?,?,50,'detector',?,?)",
                  (addr, tier, json.dumps(["split_pull"]), "2026-11-24T00:00:00Z"))
    c.execute("INSERT INTO payouts VALUES('eth',?,?,'operator',0.2,1)", (d, op))
    c.execute("INSERT INTO payouts VALUES('eth',?,?,'affiliate',0.8,1)", (d, aff))
    c.execute("INSERT INTO payouts VALUES('eth',?,?,'operator',0.2,1)", (d3, a(0x33)))     # T3 subject: not checked
    c.commit()
    return c, d, op, aff


def test_targets_refresh_cache_and_payload():
    c, d, op, aff = _db()
    assert {(t[1], t[2]) for t in freeze.targets(c)} == {(d, "drainer"), (op, "operator"), (aff, "affiliate")}
    rpc = CallRpc({(USDT, op): 5_000 * 10 ** 6, (USDC, aff): 50 * 10 ** 6, (USDT, d): 300 * 10 ** 6}, frozen={(USDT, d)})
    assert freeze.refresh(c, {"eth": rpc}, now=1_800_000_000) == 6
    assert freeze.refresh(c, {"eth": rpc}, now=1_800_000_100) == 0            # cached for 30 min
    rows, total = freeze.payload(c)
    assert [(r["address"], r["usd"], r["already_frozen"]) for r in rows] == [(op, 5000.0, False), (d, 300.0, True)]
    assert rows[0]["role"] == "operator" and rows[0]["drainer"] == d and rows[0]["drainer_tier"] == "T1"
    assert rows[0]["issuer"] == "Tether" and total == {"Tether": 5000.0}      # frozen and < 100 USD excluded
    p = build_payload(c)
    assert p["freezable"][0]["address"] == op and p["freezable_total"] == {"Tether": 5000.0}


def test_failures_never_raise():
    c, *_ = _db()

    class Bad:
        def eth_call_many(self, calls):
            raise RuntimeError("rpc down")
    assert freeze.refresh(c, {"eth": Bad()}) == 0
    assert freeze.payload(c) == ([], {})
