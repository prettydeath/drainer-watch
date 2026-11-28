"""Code classifier (codeclass.py) and the precision-audit tier policy (policy.py). Synthetic addresses only."""
import json

from drainerwatch import codeclass, policy, rollup
from drainerwatch.constants import selector
from drainerwatch.db import add_evidence
from drainerwatch.seeds import SeedSet
from tests.helpers import a, make_ctx, tx_hash

TS = 1_800_000_000
DAY = 86400
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"


def sel(*names):
    return [selector(n) for n in names]


# ---------- codeclass ----------
def test_classify_drainer_code():
    sigs = codeclass.sel_names()
    # tiny owner-gated puller (flag from bytecode.owner_gated_puller)
    assert codeclass.classify(1200, ["aabbccdd", "8da5cb5b"], flags=dict(puller=True)) == "drainer_code"
    # kit function names, resolved from the selector tables / TRON ABI
    tron = {selector("Verify20(address,address,address,uint256)"): "Verify20(address,address,address,uint256)"}
    assert codeclass.classify(2200, list(tron) + ["8da5cb5b"], sigs=tron) == "drainer_code"
    assert codeclass.classify(1300, ["11111111"], abi=["controlAndTransferToken"]) == "drainer_code"
    assert codeclass.classify(3000, ["11111111"], names=["WalletVerifier"]) == "drainer_code"
    # kit fingerprint from bytecode analysis wins over everything, also over a legit-looking name
    assert codeclass.classify(9000, [], names=["Forwarder"], flags=dict(kit="ms_drainer")) == "drainer_code"
    assert codeclass.classify(9000, sel("Claim(address)"), sigs=sigs, flags=dict(redflags=["Claim(address)"])) == "drainer_code"


def test_classify_poisoner_legit_tiny_generic_eoa():
    poison = sel("transferFrom(address[],address[],address[],uint256[])", "events()")
    assert codeclass.classify(918, poison) == "poisoner"
    assert codeclass.classify(900, ["8da5cb5b"], names=["AddressPoisoner"]) == "poisoner"
    for n in ("ERC2771Forwarder", "GnosisSafe", "SimpleAccount", "MainnetSettler", "UniversalRouter",
              "NonfungiblePositionManager", "PaymentSplitter", "OFTAdapter"):
        assert codeclass.classify(8000, ["11111111"] * 12, names=[n]) == "legit_code", n
    assert codeclass.classify(800, [], flags=dict(proxy=True, verified=True)) == "legit_code"
    assert codeclass.classify(800, [], flags=dict(safe_proxy=True)) == "legit_code"
    # a puller dispatcher that is also a big service contract is not "tiny drainer code"
    many = ["%08x" % i for i in range(12)]
    assert codeclass.classify(3000, many, flags=dict(puller=True)) == "generic"
    assert codeclass.classify(1700, ["46dd1545", "89e6b5fb", "8da5cb5b", "ef33fa81"]) == "tiny"
    erc20 = ["a9059cbb", "23b872dd", "095ea7b3", "70a08231", "18160ddd"]
    assert codeclass.classify(1700, erc20) == "generic"            # a token is not a tiny dispatcher
    assert codeclass.classify(0, []) == "eoa" and codeclass.classify(None, []) == "eoa"
    assert codeclass.classify(23, []) == "eoa"                      # EIP-7702 delegation designator


# ---------- policy units ----------
def _row(labels, victims=3, drains=3, tier="T1"):
    return dict(chain="eth", address=a(1), tier=tier, labels=sorted(labels), victims=victims, drains=drains)


def test_policy_tier_rules():
    pt = policy.policy_tier
    # kit fingerprint: T1, wins over legit code and service shapes
    assert pt(_row({"approval_fingerprint"}), "legit_code", {"deposit_sweep"}, False, False) == ("T1", None)
    assert pt(_row({"kit_pull", "owner_gated_puller"}), "generic", set(), False, False) == ("T1", None)
    # static kit labels need an observed pull
    assert pt(_row({"kit_signature"}, victims=0, drains=0), "drainer_code", set(), False, False)[0] == "T3"
    # drainer code + a pull: T1; legit code: T3; service shape: T3
    assert pt(_row({"split_pull"}), "drainer_code", set(), False, False) == ("T1", None)
    assert pt(_row({"split_xtx", "share_grid"}), "legit_code", set(), False, False) == ("T3", "legit_code_capped")
    assert pt(_row({"owner_collect"}), "generic", {"deposit_sweep"}, False, False) == ("T3", "service_shape_capped")
    # weak labels never lift a tier, alone or together
    weak = {"split_pull", "multi_victim_pull", "pays_known_operator", "cross_chain_t1", "full_balance_pull",
            "tron_eoa_pull_multi", "tron_max_approval", "prefund_approve_multi", "codehash_cluster"}
    assert pt(_row(weak), "generic", set(), False, False) == ("T3", "weak_only_capped")
    # split shapes count only on drainer-shaped contracts, and give T2 (T1 needs drainer code)
    assert pt(_row({"split_xtx"}), "tiny", set(), False, False) == ("T2", None)
    assert pt(_row({"split_xtx"}), "eoa", set(), False, False)[0] == "T3"
    assert pt(_row({"split_xtx"}), "generic", set(), False, False)[0] == "T3"
    # rescues: a permission-hijack crew, an approval spender that passes the harm test
    assert pt(_row({"perm_hijack", "perm_hijack_drain"}), "eoa", set(), True, False) == ("T2", None)
    assert pt(_row({"perm_hijack", "perm_hijack_drain"}), "eoa", set(), False, False)[0] == "T3"
    assert pt(_row({"eoa_spender_pull", "eoa_spender_multi"}), "eoa", set(), False, True) == ("T2", None)
    assert pt(_row({"eoa_spender_pull", "eoa_spender_multi"}), "eoa", set(), False, False)[0] == "T3"


def test_service_shapes_and_harm_test():
    st = policy.drain_stats
    # contract re-pulling the same victims on later days: deposit sweeper
    legs = [(TS + d * DAY, a(0x10 + v), a(0xC0), "12.345", 12.3) for v in range(2) for d in (0, 2)]
    assert policy.service_shapes(st(legs), True) == {"deposit_sweep"}
    assert policy.service_shapes(st(legs[:2]), True) == set()
    # EOA: round payments swept whole / tiny fixed fees / fan-out to many recipients
    rnd = [(TS, a(0x10 + i), a(0xC0), "500", 500.0) for i in range(4)]
    assert "deposit_sweep" in policy.service_shapes(st(rnd), False)
    fee = [(TS, a(0x10 + i), a(0xC0), "1.4973", 1.5) for i in range(4)]
    assert "gasless" in policy.service_shapes(st(fee), False)
    fan = [(TS, a(0x10 + i), a(0xD0 + i), "83.21", 83.2) for i in range(6)]
    assert "payment_fanout" in policy.service_shapes(st(fan), False)
    good = [(TS, a(0x10 + i), a(0xC0), "1174.564212", 1174.56) for i in range(4)]
    assert policy.service_shapes(st(good), False) == set() and policy.harm_ok(st(good))
    assert not policy.harm_ok(st(rnd)) and not policy.harm_ok(st(fan)) and not policy.harm_ok(None)
    unpriced = [(TS, a(0x10 + i), a(0xC0), "39447.57", None) for i in range(4)]
    assert not policy.harm_ok(st(unpriced))


# ---------- end to end through rollup ----------
def _drain(c, tx, victim, drainer, recipient, usd=1000.0, amount="1000.123", ts=TS, chain="eth"):
    c.execute("INSERT INTO drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,recipient) "
              "VALUES(?,?,0,?,?,?,?,'USDT',6,?,?,?)", (chain, tx, ts, victim, drainer, USDT, amount, usd, recipient))


def test_poisoning_category_out_of_tiers_and_totals():
    from drainerwatch.render import build_payload
    ctx = make_ctx()
    c, p = ctx.conn, a(0xB0B)
    c.execute("INSERT INTO codes VALUES('eth',?,'0xp',918,'skp',?)",
              (p, json.dumps(sel("transferFrom(address[],address[],address[],uint256[])", "events()"))))
    add_evidence(c, "eth", p, "split_pull", tx_hash(1), 1, TS, dict(spoof=True, victims=[a(0x51)]))
    add_evidence(c, "eth", p, "bytecode", tx_hash(2), 1, TS, dict(owner_gated_puller=True, size=918))
    add_evidence(c, "eth", p, "multi_victim_pull", tx_hash(3), 1, TS, dict(victims=[a(0x52), a(0x53), a(0x54)]))
    _drain(c, tx_hash(3), a(0x52), p, a(0xC0))
    c.commit()
    (r,) = rollup.rollup(c, SeedSet(), {})
    assert r["category"] == "poisoning" and r["tier"] == "T3" and r["code_class"] == "poisoner"
    pay = build_payload(c)
    assert pay["totals"]["poisoning"] == 1 and pay["totals"]["tiers"] == {"T1": 0, "T2": 0, "T3": 0}
    assert pay["contracts"] == [] and [x["address"] for x in pay["poisoning"]] == [p]
    assert pay["totals"]["usd_24h"] == 0
    assert c.execute("SELECT category, code_class FROM contracts").fetchone()[:] == ("poisoning", "poisoner")


def test_kit_evidence_wins_over_poison_labels_and_legit_names():
    ctx = make_ctx()
    c, x = ctx.conn, a(0xD1)
    add_evidence(c, "eth", x, "approval_fingerprint", tx_hash(1), 1, TS, dict(victim=a(0x51), token=USDT, kit="ms"))
    add_evidence(c, "eth", x, "poison_zero", tx_hash(2), 1, TS, dict(victim=a(0x52)))
    c.execute("INSERT INTO verified_cache VALUES('eth',?,1,'GnosisSafe',0,NULL,NULL,NULL,0)", (x,))
    c.commit()
    (r,) = rollup.rollup(c, SeedSet(), {})
    assert r["tier"] == "T1" and r["category"] is None


def test_perm_hijack_crew_t2_and_self_migration_t3():
    ctx = make_ctx(chain="tron")
    c = ctx.conn
    k1, k2, k3 = "T" + "A" * 33, "T" + "B" * 33, "T" + "C" * 33
    crew_collector, own = "T" + "D" * 33, "T" + "E" * 33
    for i, (k, victim, rc) in enumerate(((k1, "T" + "1" * 33, crew_collector), (k2, "T" + "2" * 33, crew_collector),
                                         (k3, "T" + "3" * 33, own))):
        add_evidence(c, "tron", k, "perm_hijack", tx_hash(10 + i), 1, TS, dict(victim=victim, controllers=[k]))
        add_evidence(c, "tron", k, "perm_hijack_drain", tx_hash(20 + i), 1, TS + 60, dict(victim=victim, signer=k))
        _drain(c, tx_hash(20 + i), victim, k, rc, chain="tron")
    c.commit()
    rows = {r["address"]: r for r in rollup.rollup(c, SeedSet(), {})}
    assert rows[k1]["rule_tier"] == "T1" and rows[k1]["tier"] == "T2" and rows[k2]["tier"] == "T2"
    assert rows[k3]["tier"] == "T3"                      # pays its own recipient: no crew


def test_legit_code_caps_split_contract():
    ctx = make_ctx()
    c, x = ctx.conn, a(0xF0)
    c.execute("INSERT INTO codes VALUES('eth',?,'0xf',1500,'skf','[\"aabbccdd\",\"8da5cb5b\"]')", (x,))
    add_evidence(c, "eth", x, "split_xtx", tx_hash(1), 1, TS,
                 dict(victims=[a(0x51), a(0x52), a(0x53)], recipients=[dict(wallet=a(0xD1), share=0.8)]))
    c.commit()
    (r,) = rollup.rollup(c, SeedSet(), {})
    assert (r["code_class"], r["tier"]) == ("tiny", "T2")           # drainer-shaped, no pull dispatcher: T2
    c.execute("INSERT INTO verified_cache VALUES('eth',?,1,'ERC2771Forwarder',0,NULL,NULL,NULL,0)", (x,))
    c.commit()
    (r,) = rollup.rollup(c, SeedSet(), {})
    assert r["code_class"] == "legit_code" and r["tier"] == "T3"
