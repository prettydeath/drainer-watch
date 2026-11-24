from drainerwatch import render, wallets
from tests.helpers import a, make_ctx, tx_hash


def _contract(conn, addr, tier, usd=0.0):
    conn.execute("INSERT INTO contracts(chain,address,tier,score,source,labels,first_seen,last_seen,victims,drains,usd) "
                 "VALUES('eth',?,?,50,'detector','[]','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',1,1,?)", (addr, tier, usd))


def _drain(conn, n, drainer, recipient, usd, ts):
    conn.execute("INSERT INTO drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,recipient) "
                 "VALUES('eth',?,0,?,?,?,?,'USDT',6,'1',?,?)", (tx_hash(n), ts, a(900 + n), drainer, a(50), usd, recipient))


def test_wallet_aggregate_from_full_drains_table():
    ctx = make_ctx()
    c = ctx.conn
    d1, d2, d3, coll, other = a(1), a(2), a(3), a(10), a(11)
    _contract(c, d1, "T1", 300)
    _contract(c, d2, "T2", 50)
    _contract(c, d3, "T3", 5)
    c.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'collector',0,2)", (d1, coll))
    c.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'operator',0.2,1)", (d2, coll))
    c.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'collector',0,1)", (d3, other))
    _drain(c, 1, d1, coll, 100.0, 1000)
    _drain(c, 2, d1, coll, 200.0, 3000)
    _drain(c, 3, d2, coll, 50.0, 2000)
    _drain(c, 4, d1, d1, 9.0, 4000)                     # to the drainer itself: not an inflow of coll
    c.execute("INSERT INTO vasp_links(chain,subject,subject_role,counterparty,kind,entity,category,tx,tx_in,ts,amount,symbol,usd,"
              "confidence) VALUES('eth',?,'collector',?,'direct','Binance','cex','0xout',NULL,5000,'1','USDT',40,'high')",
              (coll, a(77)))
    p = render.build_payload(c)
    w = p["wallets"]
    assert list(w) == ["eth:" + coll, "eth:" + other]   # T1/T2 payout wallets first, then operators[] (any tier)
    x = w["eth:" + coll]
    assert x["roles"] == ["collector", "operator"]
    assert x["n_in"] == 3 and x["total_in_usd"] == 350.0
    assert x["first_in"].endswith("Z") and x["first_in"] < x["last_in"]
    assert [i["usd"] for i in x["inflows"]] == [200.0, 50.0, 100.0]          # newest first
    assert [(d["drainer"], d["tier"], d["usd"], d["txs"]) for d in x["drainers"]] == [(d1, "T1", 300.0, 2), (d2, "T2", 50.0, 1)]
    assert x["drainers"][1]["share"] == 0.2 and x["drainers"][1]["role"] == "operator"
    assert x["outflows_known"][0]["entity"] == "Binance" and x["outflows_known"][0]["usd"] == 40.0


def test_wallet_caps_and_priority():
    ctx = make_ctx()
    c = ctx.conn
    for i in range(5):
        _contract(c, a(100 + i), "T1", 10 * i)
        c.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'collector',0,1)", (a(100 + i), a(200 + i)))
        for j in range(4):
            _drain(c, 1000 + 10 * i + j, a(100 + i), a(200 + i), 1.0, 100 + j)
    frz = [dict(chain="eth", address=a(300), role="operator")]
    contracts = [dict(chain="eth", address=a(100 + i), tier="T1", usd=10 * i, payouts=[dict(wallet=a(200 + i), role="collector")])
                 for i in range(5)]
    out = wallets.payload(c, contracts, frz, [], limit=3, per=2)
    assert list(out) == ["eth:" + a(300), "eth:" + a(204), "eth:" + a(203)]      # freezable first, then by subject usd
    assert out["eth:" + a(300)]["n_in"] == 0 and out["eth:" + a(300)]["roles"] == ["operator"]
    assert len(out["eth:" + a(204)]["inflows"]) == 2 and out["eth:" + a(204)]["n_in"] == 4
