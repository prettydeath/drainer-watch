"""fpguard: custodial sweeps / custody contracts that look like large generic pulls are capped at T3."""
import json

from drainerwatch import fpguard, render
from drainerwatch.db import connect
from tests.helpers import a, tx_hash

DAY = 86400
T0 = 1_800_000_000
SPENDER, SINK = a(1), a(2)


def _drain(conn, n, victim, usd, ts, amount=None, drainer=SPENDER, recipient=SINK, chain="eth"):
    conn.execute("INSERT INTO drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,recipient) "
                 "VALUES(?,?,0,?,?,?,'tok','USDT',6,?,?,?)",
                 (chain, tx_hash(n), ts, victim, drainer, amount or f"{usd:.2f}".rstrip("0").rstrip(".") + ".37", usd, recipient))


def _hist(conn, addr, funders=(), out_n=0, out_sinks=0, in_n=0, chain="eth", in_senders=None, out_usd=None,
          created_at=None, contract_name=None):
    fpguard.ensure_schema(conn)
    conn.execute("INSERT OR REPLACE INTO addr_history(chain,address,funders,out_n,out_sinks,in_n,checked_at,in_senders,"
                 "out_usd,created_at,contract_name) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                 (chain, addr, json.dumps(list(funders)), out_n, out_sinks, in_n, T0, in_senders, out_usd, created_at,
                  contract_name))


def _row(labels=("eoa_spender_pull", "eoa_spender_multi"), usd=1_000_000, tier="T2", addr=SPENDER, name=None):
    return dict(chain="eth", address=addr, tier=tier, labels=sorted(labels), usd=usd, contract_name=name)


def _capped(conn, row):
    fpguard.apply_caps(conn, [row])
    return row["tier"] == "T3", set(row["labels"])


def test_is_round():
    assert fpguard.is_round("4000000.0001") and fpguard.is_round("300000") and fpguard.is_round("1000")
    assert not fpguard.is_round("128185") and not fpguard.is_round("11999999.934") and not fpguard.is_round("500.0")
    assert not fpguard.is_round("1000.5") and not fpguard.is_round("x")


def test_real_drainer_one_off_victims_not_capped():
    c = connect(":memory:")
    for i in range(10):                                     # ten wallets emptied once each, odd amounts
        _drain(c, i, a(100 + i), 120_000 + i, T0 + i * 3 * DAY)
    capped, lb = _capped(c, _row())
    assert not capped and "service_sweep_capped" not in lb


def test_repeat_victim_on_several_days_is_a_sweep():
    c = connect(":memory:")
    n = 0
    for v in range(3):
        for k in range(4):                                  # each "victim" pulled 4 times over 4 days
            _drain(c, n, a(100 + v), 100_000, T0 + k * DAY)
            n += 1
    capped, lb = _capped(c, _row())
    assert capped and {"service_sweep_capped", "fp_repeat_victim"} <= lb


def test_repeat_pulls_within_one_day_are_not_a_sweep():
    c = connect(":memory:")
    for k in range(5):
        _drain(c, k, a(100), 100_000, T0 + k * 60)
    assert not _capped(c, _row())[0]


def test_same_owner_spender_funded_victim():
    c = connect(":memory:")
    _drain(c, 1, a(100), 4_000_000, T0)
    _drain(c, 2, a(101), 2_000_000, T0 + DAY)
    _drain(c, 3, a(102), 100_000, T0 + 2 * DAY)
    _hist(c, a(100), funders=[SPENDER])
    _hist(c, a(101), funders=[a(55), SPENDER])
    capped, lb = _capped(c, _row())
    assert capped and "fp_same_owner" in lb


def test_same_owner_victim_funded_spender():
    c = connect(":memory:")                                 # company hot wallet funded its own operator key
    _drain(c, 1, a(100), 3_000_000, T0)
    _hist(c, SPENDER, funders=[a(100)])
    assert "fp_same_owner" in _capped(c, _row())[1]


def test_same_owner_recipient_funded_by_victim():
    c = connect(":memory:")
    _drain(c, 1, a(100), 3_000_000, T0)
    _hist(c, SINK, funders=[a(100)])
    assert _capped(c, _row())[0]


def test_deposit_address_victims():
    c = connect(":memory:")
    _drain(c, 1, a(100), 900_000, T0)
    _drain(c, 2, a(101), 50_000, T0)
    _hist(c, a(100), out_n=37, out_sinks=4, in_n=43)        # deposit address swept 37 times to 4 sinks
    _hist(c, a(101), out_n=37, out_sinks=30, in_n=43)       # a normal wallet: many different counterparties
    capped, lb = _capped(c, _row())
    assert capped and "fp_deposit_address" in lb


def test_round_amounts_need_two_legs():
    c = connect(":memory:")
    _drain(c, 1, a(100), 4_000_000, T0, amount="4000000.0001")
    _drain(c, 2, a(101), 50_000, T0)
    assert not _capped(c, _row())[0]                        # one round pull alone proves nothing
    _drain(c, 3, a(102), 300_000, T0, amount="300000.0001")
    capped, lb = _capped(c, _row())
    assert capped and "fp_round_amounts" in lb


def test_service_share_threshold():
    c = connect(":memory:")
    _drain(c, 1, a(100), 400_000, T0)
    _drain(c, 2, a(101), 600_000, T0)
    _hist(c, a(100), funders=[SPENDER])                     # 40 % on a same-owner leg: below FP_SERVICE_SHARE
    assert not _capped(c, _row())[0]


def test_kit_evidence_and_small_subjects_are_never_capped():
    c = connect(":memory:")
    for k in range(4):
        _drain(c, k, a(100), 100_000, T0 + k * DAY)
    assert not _capped(c, _row(labels=("tron_eoa_pull", "approval_fingerprint")))[0]
    assert not _capped(c, _row(usd=fpguard.FP_CHECK_MIN_USD - 1))[0]
    r = _row(tier="T3")                                     # T3 stays T3, nothing added
    fpguard.apply_caps(c, [r])
    assert "service_sweep_capped" not in r["labels"]


def test_custody_contract_names():
    c = connect(":memory:")
    assert fpguard.is_custody_name("WalletSimple") and fpguard.is_custody_name("? (proxy of WalletSimple)")
    assert not fpguard.is_custody_name("SafeProxy") and not fpguard.is_custody_name(None)
    capped, lb = _capped(c, _row(labels=("split_pull",), usd=10, name="WalletSimple"))
    assert capped and "custody_contract_capped" in lb


def _contract(conn, addr, tier, labels, usd):
    conn.execute("INSERT INTO contracts(chain,address,tier,score,source,labels,first_seen,last_seen,victims,drains,usd) "
                 "VALUES('eth',?,?,50,'detector',?,'2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',1,1,?)",
                 (addr, tier, json.dumps(labels), usd))


def test_capped_subjects_leave_totals_and_operators():
    c = connect(":memory:")
    real, svc = a(10), a(11)
    _contract(c, real, "T2", ["eoa_spender_pull"], 500)
    _contract(c, svc, "T3", ["eoa_spender_pull", "service_sweep_capped", "fp_same_owner"], 9_000_000)
    for d, w in ((real, a(20)), (svc, a(21))):
        c.execute("INSERT INTO payouts(chain,drainer,wallet,role,share,txs) VALUES('eth',?,?,'collector',0,1)", (d, w))
    import time
    now = int(time.time())
    _drain(c, 1, a(100), 500, now - 60, drainer=real, recipient=a(20))
    _drain(c, 2, a(101), 9_000_000, now - 60, drainer=svc, recipient=a(21))
    p = render.build_payload(c)
    assert p["totals"]["usd_24h"] == 500
    assert [o["wallet"] for o in p["operators"]] == [a(20)]


class FakeES:
    enabled = True

    def __init__(self, data):
        self.data, self.calls = data, []

    def call(self, chain, params):
        self.calls.append((params["action"], params["address"]))
        return self.data.get((params["action"], params["address"]), [])


class FakeTG:
    def __init__(self):
        self.seen = []

    def history(self, a_):
        self.seen.append(a_)
        return dict(funders=["TFunder"], out_n=12, out_sinks=2, in_n=20, in_senders=3, out_usd=0.0, created_at=None)

    def contract_name(self, a_):
        return None


def test_lookup_history_evm_and_tron_then_cache():
    c = connect(":memory:")
    v1 = a(100)
    _drain(c, 1, v1, 3_000_000, T0)
    _drain(c, 2, "TVictim", 2_000_000, T0, drainer="TSpender", recipient="TSink", chain="tron")
    es = FakeES({("txlist", v1): [dict(**{"from": SPENDER, "to": v1, "value": "5", "timeStamp": "1700000000"})],
                 ("tokentx", v1): [dict(**{"from": v1, "to": SINK, "tokenSymbol": "USDT", "tokenDecimal": "6",
                                           "value": "1000000", "timeStamp": "1700000500"})] * 12
                 + [dict(**{"from": a(7), "to": v1, "tokenSymbol": "XYZ", "value": "1"})] * 6})
    tg = FakeTG()
    rows = [_row(), dict(chain="tron", address="TSpender", tier="T2", labels=["tron_eoa_pull"], usd=2_000_000)]
    n = fpguard.lookup_history(c, es, rows, tg=tg, now=T0)
    assert n == 6                                           # subject + victim + recipient on each chain
    h = fpguard.load_history(c)
    assert h[("eth", v1)] == dict(funders=[SPENDER], out_n=12, out_sinks=1, in_n=6, in_senders=1, out_usd=12.0,
                                  created_at=1700000000, contract_name=None)
    assert sorted(tg.seen) == ["TSink", "TSpender", "TVictim"]
    assert fpguard.lookup_history(c, es, rows, tg=tg, now=T0 + 60) == 0     # cached
    r = _row()
    fpguard.apply_caps(c, [r])
    assert r["tier"] == "T3" and {"fp_same_owner", "fp_deposit_address"} <= set(r["labels"])


def test_repeat_victim_alone_does_not_cap_a_split_subject():
    c = connect(":memory:")
    n = 0
    for v in range(3):
        for k in range(4):
            _drain(c, n, a(100 + v), 100_000, T0 + k * DAY)
            n += 1
    assert not _capped(c, _row(labels=("split_xtx", "tron_eoa_pull")))[0]
    _hist(c, a(100), funders=[SPENDER])
    _hist(c, a(101), out_n=20, out_sinks=2, in_n=20)
    capped, lb = _capped(c, _row(labels=("split_xtx", "tron_eoa_pull")))
    assert capped and "fp_repeat_victim" not in lb and {"fp_same_owner", "fp_deposit_address"} <= lb


# ---------- Arkham Intel ----------
def _ark(conn, addr, entity=None, etype=None, service=None, label=None, deposit=None, chain="eth"):
    conn.execute(fpguard.ARKHAM_SCHEMA)
    conn.execute("INSERT OR REPLACE INTO arkham_cache VALUES(?,?,?,?,?,?,?,?,?)",
                 (chain, addr, entity, (entity or "").lower() or None, etype,
                  None if service is None else int(service), label, deposit, T0))


def _one_victim(c, usd=2_000_000):
    _drain(c, 1, a(100), usd, T0)
    _drain(c, 2, a(101), usd // 4, T0 + DAY)


def test_arkham_service_subject_is_capped():
    c = connect(":memory:")
    _one_victim(c)
    _ark(c, SPENDER, "Kraken", "cex", True, "Deposit Sweeper")
    capped, lb = _capped(c, _row())
    assert capped and {"fp_arkham_entity", "service_sweep_capped"} <= lb


def test_arkham_service_victim_or_hot_wallet_recipient_makes_the_leg_service():
    c = connect(":memory:")
    _one_victim(c)
    _ark(c, a(100), "Cumberland", "otc", True)
    assert "fp_arkham_entity" in _capped(c, _row())[1]
    c2 = connect(":memory:")
    _one_victim(c2)
    _ark(c2, SINK, "Kraken", "cex", True, "Hot Wallet 5")
    assert _capped(c2, _row())[0]


def test_arkham_deposit_recipient_alone_does_not_cap():
    c = connect(":memory:")                                 # drainers cash out into exchange deposit addresses
    _one_victim(c)
    _ark(c, SINK, "Bitget", "cex", True, "Deposit", deposit="bitget")
    assert not _capped(c, _row())[0]


def test_arkham_individual_and_predicted_do_not_count():
    c = connect(":memory:")
    _one_victim(c)
    _ark(c, SPENDER, "Some Person", "individual", False)
    assert not _capped(c, _row())[0]


def test_arkham_malicious_is_never_capped():
    c = connect(":memory:")
    for k in range(4):
        _drain(c, k, a(100), 500_000, T0 + k * DAY)         # would be a repeat-victim sweep
    _ark(c, SINK, "Inferno Drainer", "scam", False, "Inferno Drainer: Fee Recipient")
    capped, lb = _capped(c, _row())
    assert not capped and "arkham_malicious" in lb


def test_parse_arkham_uses_confirmed_entity_only():
    x = fpguard.parse_arkham({"address": "0xA", "arkhamEntity": {"name": "Binance", "id": "binance", "type": "cex",
                                                                 "service": True},
                              "arkhamLabel": {"name": "Hot Wallet"}, "depositServiceID": None,
                              "predictedEntity": {"name": "Other", "type": "cex"}})
    assert x == dict(entity="Binance", entity_id="binance", entity_type="cex", service=True, label="Hot Wallet",
                     deposit_service=None)
    y = fpguard.parse_arkham({"address": "0xB", "predictedEntity": {"name": "Other", "type": "cex"}})
    assert y["entity"] is None and not fpguard.arkham_service(y)


def test_lookup_arkham_needs_key_batches_per_chain_and_caches(monkeypatch):
    c = connect(":memory:")
    _drain(c, 1, a(100), 3_000_000, T0)
    _drain(c, 2, "TVictim", 2_000_000, T0, drainer="TSpender", recipient="TSink", chain="tron")
    rows = [_row(usd=3_000_000), dict(chain="tron", address="TSpender", tier="T2", labels=["tron_eoa_pull"], usd=2_000_000),
            _row(addr=a(5), usd=100_000)]               # below ARKHAM_MIN_USD: not sent
    calls = []

    def fake(chain, addrs, key):
        calls.append((chain, sorted(addrs), key))
        if chain == "eth":   # checksummed keys come back; matched case-insensitively on EVM
            return {SPENDER.upper().replace("0X", "0x"): {"arkhamEntity": {"name": "Kraken", "id": "kraken", "type": "cex",
                                                                          "service": True}}}
        return {}
    monkeypatch.delenv("ARKHAM_API_KEY", raising=False)
    assert fpguard.lookup_arkham(c, rows, now=T0, batch=fake) == 0 and calls == []
    monkeypatch.setenv("ARKHAM_API_KEY", "k")
    assert fpguard.lookup_arkham(c, rows, now=T0, batch=fake) == 6
    assert sorted(ch for ch, _, _ in calls) == ["eth", "tron"] and all(k == "k" for _, _, k in calls)
    assert sorted(calls[0][1] if calls[0][0] == "eth" else calls[1][1]) == sorted([SPENDER, SINK, a(100)])
    assert fpguard.lookup_arkham(c, rows, now=T0 + 60, batch=fake) == 0      # cached, unattributed ones too
    ark = fpguard.load_arkham(c)
    assert ark[("eth", SPENDER)]["entity"] == "Kraken" and ("tron", "TSpender") not in ark
    r = _row(usd=3_000_000)
    fpguard.apply_caps(c, [r])
    assert r["tier"] == "T3" and "fp_arkham_entity" in r["labels"]


def test_arkham_attached_to_data_json_contracts():
    c = connect(":memory:")
    _one_victim(c)
    _ark(c, SPENDER, "Kraken", "cex", True, "Deposit Sweeper")
    _ark(c, a(100), None, None, None, "Deposit", deposit="kraken")
    cs = [dict(chain="eth", address=SPENDER, payouts=[dict(wallet=SINK, role="collector")]), dict(chain="eth", address=a(9))]
    fpguard.arkham_for_contracts(c, cs)
    assert [(x["role"], x["entity"], x["deposit_service"]) for x in cs[0]["arkham"]] == [("subject", "Kraken", None),
                                                                                       ("victim", None, "kraken")]
    assert "arkham" not in cs[1]


# ---------- DEX pool / aggregator / distributor / pipeline ----------
POOL = a(3)


def test_dex_pool_trading_wallet_is_capped_even_with_a_split():
    c = connect(":memory:")
    for k in range(8):                                      # one wallet trading through pools over 8 days
        _drain(c, k, a(100), 20_000, T0 + k * DAY, recipient=POOL)
    _hist(c, POOL, contract_name="UniswapV2Pair")
    capped, lb = _capped(c, _row(labels=("split_pull", "share_grid", "pays_inferred_operator"), usd=160_000))
    assert capped and "fp_dex_pool" in lb


def test_dex_pool_by_selectors_or_label():
    c = connect(":memory:")
    for k in range(6):
        _drain(c, k, a(100), 20_000, T0 + k * DAY, recipient=POOL)
    c.execute("INSERT INTO codes(chain,address,code_hash,size,skeleton,selectors) VALUES('eth',?,?,1,'',?)",
              (POOL, "h", json.dumps(["0dfe1681", "d21220a7", "022c0d9f"])))
    assert _capped(c, _row(usd=120_000))[0]
    assert fpguard.is_pool(category="dex") and not fpguard.is_pool(name="TetherToken")


def test_drainer_swapping_loot_once_per_victim_is_not_a_pool_trade():
    c = connect(":memory:")
    for v in range(10):                                     # ten victims, each emptied once into a pool (swap to ETH)
        _drain(c, v, a(100 + v), 20_000, T0 + v * DAY, recipient=POOL)
    _hist(c, POOL, contract_name="UniswapV2Pair")
    assert not _capped(c, _row(usd=200_000))[0]


def test_aggregator_recipient_collects_from_far_more_senders_than_victims():
    c = connect(":memory:")
    for v in range(5):
        _drain(c, v, a(100 + v), 50_000, T0 + v * 3600)
    _hist(c, SINK, in_senders=180, out_sinks=1, out_n=3, in_n=197)
    capped, lb = _capped(c, _row(usd=250_000))
    assert capped and "fp_aggregator" in lb


def test_drainer_collector_with_many_victims_is_not_an_aggregator():
    c = connect(":memory:")
    for v in range(60):                                     # 60 victims -> 120 senders is only 2x the victims
        _drain(c, v, a(100 + v), 5_000, T0 + v * 3600)
    _hist(c, SINK, in_senders=120, out_sinks=4, out_n=20, in_n=180)
    assert not _capped(c, _row(usd=300_000))[0]


def test_distributor_recipient():
    c = connect(":memory:")
    _drain(c, 1, a(100), 300_000, T0)
    _hist(c, SINK, in_senders=1, out_sinks=152, out_n=198, in_n=2)
    capped, lb = _capped(c, _row(usd=300_000))
    assert capped and "fp_distributor" in lb


def test_pipeline_recipient_old_high_volume_few_senders():
    c = connect(":memory:")
    _drain(c, 1, a(100), 900_000, T0)
    _drain(c, 2, a(101), 600_000, T0 + DAY)
    _hist(c, SINK, in_senders=7, out_sinks=2, out_n=188, in_n=12, out_usd=17_400_000, created_at=T0 - 400 * DAY)
    capped, lb = _capped(c, _row(labels=("split_xtx", "tron_contract_pull"), usd=1_500_000))
    assert capped and "fp_pipeline" in lb


def test_pipeline_needs_age_volume_and_few_senders():
    for kw in (dict(created_at=T0 - 30 * DAY, out_usd=17_400_000, in_senders=7),     # young wallet
               dict(created_at=T0 - 400 * DAY, out_usd=2_000_000, in_senders=7),     # little volume
               dict(created_at=T0 - 400 * DAY, out_usd=17_400_000, in_senders=60)):  # many senders: an operator wallet
        c = connect(":memory:")
        _drain(c, 1, a(100), 900_000, T0)
        _drain(c, 2, a(101), 600_000, T0 + DAY)
        _hist(c, SINK, out_sinks=2, out_n=188, in_n=12, **kw)
        assert not _capped(c, _row(usd=1_500_000))[0], kw


def test_split_legs_are_judged_by_their_own_recipient():
    c = connect(":memory:")
    _drain(c, 1, a(100), 900_000, T0, recipient=SINK)      # 90 % into a payout hot wallet
    _drain(c, 2, a(100), 100_000, T0, recipient=a(4))      # 10 % share to an unknown wallet
    _hist(c, SINK, in_senders=1, out_sinks=152)
    assert _capped(c, _row(labels=("split_pull",), usd=1_000_000))[0]
    c2 = connect(":memory:")
    _drain(c2, 1, a(100), 500_000, T0, recipient=SINK)     # only half on the service leg: below FP_SERVICE_SHARE
    _drain(c2, 2, a(100), 500_000, T0, recipient=a(4))
    _hist(c2, SINK, in_senders=1, out_sinks=152)
    assert not _capped(c2, _row(labels=("split_pull",), usd=1_000_000))[0]


def test_addr_history_migrates_old_table():
    c = connect(":memory:")
    c.execute("CREATE TABLE addr_history(chain TEXT NOT NULL, address TEXT NOT NULL, funders TEXT, out_n INTEGER, "
              "out_sinks INTEGER, in_n INTEGER, checked_at INTEGER, PRIMARY KEY(chain, address))")
    c.execute("INSERT INTO addr_history VALUES('eth',?,'[]',1,1,1,1)", (a(9),))
    h = fpguard.load_history(c)
    assert h[("eth", a(9))]["in_senders"] is None and h[("eth", a(9))]["out_n"] == 1
