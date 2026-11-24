"""Family names: kit > self-given contract name (impersonation marked) > token name > dispatcher functions > hash."""
import json

from drainerwatch import famname
from drainerwatch.render import build_payload
from drainerwatch.util import selector
from tests.helpers import a, make_ctx

V20, V10 = selector("Verify20(address,address,address,uint256)"), selector("Verify10(address,uint256)")
DR = selector("drainAll(address)")


def m(**kw):
    return dict(dict(kit=None, contract_name=None, legit=False, token_name=None, token_symbol=None, selectors=set(), sig={}), **kw)


def test_priority_order():
    assert famname.pick("ms_drainer", [m()]) == ("MS Drainer", "kit")
    assert famname.pick("f_aaaaaa", [m(kit="verify_account"), m(contract_name="X")]) == ("VerifyAccount", "kit")
    assert famname.pick("f_aaaaaa", [m(contract_name="heyue"), m(contract_name="heyue"), m(contract_name="Other")]) == \
        ("heyue", "contract_name")
    assert famname.pick("f_aaaaaa", [m(contract_name="SunSwapV4")]) == \
        ('self-named "SunSwapV4" (not the real SunSwap)', "contract_name")
    assert famname.pick("f_aaaaaa", [m(token_symbol="USDT", selectors={"a9059cbb"})])[1] == "token_name"
    sig = {V20: "Verify20(address,address,address,uint256)", V10: "Verify10(address,uint256)",
           "8da5cb5b": "owner()", "a9059cbb": "transfer(address,uint256)"}
    got = famname.pick("f_9439c5", [m(selectors={V20, V10, "8da5cb5b", "a9059cbb"}, sig=sig)])
    assert got == ("Verify10/Verify20 contract", "functions")
    assert famname.pick("f_9439c5", [m(selectors={"8da5cb5b"}, sig=sig)]) == ("Unnamed code family 9439c5", "hash")


def test_payload_carries_family_name_fields():
    ctx = make_ctx()
    c = ctx.conn
    x = a(0xF00D)
    c.execute("INSERT INTO contracts(chain,address,tier,score,source,family,labels,victims,drains,usd) "
              "VALUES('eth',?,'T2',50,'detector','f_9439c5',?,1,1,0)", (x, json.dumps(["split_pull"])))
    c.execute("INSERT INTO codes VALUES('eth',?,'0x',500,'sk',?)", (x, json.dumps([V20, DR])))
    famname.ensure_tables(c)
    c.executemany("INSERT INTO sig_names VALUES(?,?,1)", [(V20, "Verify20(address,address,address,uint256)"),
                                                         (DR, "drainAll(address)")])
    c.commit()
    p = build_payload(c)
    (r,) = p["contracts"]
    assert r["family"] == "f_9439c5" and r["family_name"] == "Verify20/drainAll contract"
    assert r["family_name_source"] == "functions"
    (f,) = p["families"]
    assert f["family_name"] == r["family_name"] and f["family_name_source"] == "functions"
