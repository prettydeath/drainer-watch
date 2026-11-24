"""Open allowances of approval-based subjects, code status of T1/T2, MS one-shot spender label (fake RPC)."""

from drainerwatch import exposure, famname, rollup
from drainerwatch.db import add_evidence
from drainerwatch.render import build_payload
from drainerwatch.seeds import SeedSet
from tests.helpers import a, make_ctx, tx_hash

USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
KIT = 0xb88e282822ab5ed106947c1c60af583c1741a38e858de00000


class FakeRpc:
    def __init__(self, allow, bal, codes=None, nonces=None):
        self.allow, self.bal, self.codes, self.nonce = allow, bal, codes or {}, nonces or {}

    def get_code_many(self, addrs):
        return {x: self.codes.get(x, "0x") for x in addrs}

    def nonces(self, addrs):
        return {x: self.nonce.get(x, 0) for x in addrs}

    def eth_call_many(self, calls):
        out = []
        for to, data in calls:
            sel = data[2:10]
            if sel == exposure.SEL_ALLOWANCE:
                owner, sp = "0x" + data[34:74], "0x" + data[98:138]
                out.append("0x" + f"{self.allow.get((owner, sp), 0):064x}")
            else:
                out.append("0x" + f"{self.bal.get('0x' + data[-40:], 0):064x}")
        return out


class Toks:
    def get(self, t):
        return ("USDT", 6)


class Px:
    def usd(self, chain, token, raw, dec):
        return round(raw / 10 ** dec, 2)


def _db():
    c = make_ctx().conn
    sp, v = a(0x5A), a(0x71)
    add_evidence(c, "eth", sp, "approval_fingerprint", tx_hash(1), 1, 1_800_000_000, dict(victim=v, token=USDT, kit="ms_drainer"))
    c.commit()
    rollup.rollup(c, SeedSet(), {})
    return c, sp, v


def test_open_allowance_code_status_and_oneshot_spender():
    c, sp, v = _db()
    rpc = FakeRpc({(v, sp): KIT}, {v: 2_500 * 10 ** 6}, nonces={sp: 0})
    assert exposure.resolve_codes(c, {"eth": rpc}) == 1
    exposure.resolve_nonces(c, {"eth": rpc})
    assert exposure.refresh(c, {"eth": rpc}, tokens_of=lambda ch: Toks(), prices=Px()) == 1
    assert exposure.refresh(c, {"eth": rpc}, tokens_of=lambda ch: Toks(), prices=Px()) == 0      # cached
    rows = {r["address"]: r for r in rollup.rollup(c, SeedSet(), {})}
    assert rows[sp]["tier"] == "T1" and "oneshot_spender" in rows[sp]["labels"] and rows[sp]["is_contract"] == 0
    assert rows[sp]["family"] == "ms_oneshot_spender"
    p = build_payload(c)
    (r,) = p["contracts"]
    assert r["is_contract"] is False and r["pulled"] is False
    assert r["family_name"] == "MS Drainer one-shot spender (wallet randomizer)" and r["family_name_source"] == "kit"
    (o,) = r["open_allowances"]
    assert o["allowance"] == "unlimited" and o["usd_at_risk"] == 2500.0 and o["victim"] == v and not o["pulled"]
    assert p["exposure_total_usd"] == 2500.0


def test_used_spender_is_not_oneshot_and_revoked_allowance_hidden():
    c, sp, v = _db()
    rpc = FakeRpc({}, {v: 10}, nonces={sp: 40})
    exposure.resolve_codes(c, {"eth": rpc})
    exposure.resolve_nonces(c, {"eth": rpc})
    exposure.refresh(c, {"eth": rpc}, tokens_of=lambda ch: Toks(), prices=Px())
    rows = {r["address"]: r for r in rollup.rollup(c, SeedSet(), {})}
    assert "oneshot_spender" not in rows[sp]["labels"]
    p = build_payload(c)
    assert p["contracts"][0]["open_allowances"] == [] and p["exposure_total_usd"] == 0
    assert famname.KIT_NAMES["ms_oneshot_spender"].startswith("MS Drainer")
