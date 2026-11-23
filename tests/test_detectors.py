from drainerwatch import detectors
from drainerwatch.constants import ALLOWLIST
from drainerwatch.rpc import parse_logs
from drainerwatch.seeds import SeedSet
from tests.helpers import a, approval_log, transfer_log, tx_hash

TOKEN = a(0xAAA)
VICTIM, OP, AFF, DRAINER, ATTACKER = a(1), a(2), a(3), a(4), a(5)


def parsed(*logs):
    return parse_logs(list(logs))


def never_allowed(_):
    return False


def allowed(addr):
    return addr in ALLOWLIST


def split_logs(tx=1, victim=VICTIM, token=TOKEN, amounts=(2000, 8000)):
    return [transfer_log(tx_hash(tx), token, victim, OP, amounts[0], li=0),
            transfer_log(tx_hash(tx), token, victim, AFF, amounts[1], li=1)]


def test_d2_candidate_and_confirm():
    tr, _ = parsed(*split_logs())
    c = detectors.d2_candidates(tr, never_allowed)
    assert len(c) == 1 and c[0]["victim"] == VICTIM
    res = detectors.d2_confirm(c[0], {"from": ATTACKER, "to": DRAINER}, lambda x: x == DRAINER, never_allowed)
    assert res["drainer"] == DRAINER
    roles = {r["wallet"]: r["role"] for r in res["recipients"]}
    assert roles == {AFF: "affiliate", OP: "operator"}      # larger share = affiliate


def test_d2_share_bounds():
    for amounts in [(5000, 5000), (100, 9900), (500, 9500)]:       # 50 %, 99 %, exactly 95 % is allowed
        tr, _ = parsed(*split_logs(amounts=amounts))
        got = detectors.d2_candidates(tr, never_allowed)
        assert bool(got) == (amounts == (500, 9500))
    tr, _ = parsed(transfer_log(tx_hash(1), TOKEN, VICTIM, OP, 10))
    assert detectors.d2_candidates(tr, never_allowed) == []         # one leg only
    tr, _ = parsed(transfer_log(tx_hash(1), TOKEN, VICTIM, OP, 2), transfer_log(tx_hash(1), TOKEN, VICTIM, OP, 8, li=1))
    assert detectors.d2_candidates(tr, never_allowed) == []         # same recipient twice


def test_d2_negative_allowlisted_tx_to():
    tr, _ = parsed(*split_logs())
    c = detectors.d2_candidates(tr, allowed)[0]
    cow = "0x9008d19f58aabd9ed0d60971565aa8510560ab41"
    assert cow in ALLOWLIST
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": cow}, lambda x: True, allowed) is None


def test_d2_negative_tx_from_is_victim():
    tr, _ = parsed(*split_logs())
    c = detectors.d2_candidates(tr, never_allowed)[0]
    assert detectors.d2_confirm(c, {"from": VICTIM, "to": DRAINER}, lambda x: x == DRAINER, never_allowed) is None


def test_d2_negative_victim_is_contract_or_drainer_is_eoa():
    tr, _ = parsed(*split_logs())
    c = detectors.d2_candidates(tr, never_allowed)[0]
    both = lambda x: x in (VICTIM, DRAINER)  # noqa: E731
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": DRAINER}, both, never_allowed) is None
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": DRAINER}, lambda x: False, never_allowed) is None


def test_d2_negative_zero_from_and_token_target():
    tr, _ = parsed(*split_logs(victim="0x" + "0" * 40))
    assert detectors.d2_candidates(tr, never_allowed) == []
    tr, _ = parsed(*split_logs())
    c = detectors.d2_candidates(tr, never_allowed)[0]
    assert detectors.d2_confirm(c, {"from": ATTACKER, "to": TOKEN}, lambda x: x == TOKEN, never_allowed) is None


def test_d3_multi_victim_pull():
    victims = [a(10), a(11), a(12)]
    logs = [transfer_log(tx_hash(7), TOKEN, v, OP, 100 + i, li=i) for i, v in enumerate(victims)]
    tr, _ = parsed(*logs)
    owner_spenders = {v: {DRAINER} for v in victims}
    by_tx = detectors.d3_candidates(tr, owner_spenders, set(), set())
    assert list(by_tx) == [tx_hash(7)]
    res = detectors.d3_confirm(by_tx[tx_hash(7)], {"from": ATTACKER, "to": DRAINER}, owner_spenders,
                               set(), lambda x: x == DRAINER, never_allowed)
    assert res["drainer"] == DRAINER and res["victims"] == sorted(victims)
    # approved a different spender -> not a victim of this contract
    assert detectors.d3_confirm(by_tx[tx_hash(7)], {"from": ATTACKER, "to": a(99)}, owner_spenders, set(),
                                lambda x: x == a(99), never_allowed) is None
    # allowlisted target
    assert detectors.d3_confirm(by_tx[tx_hash(7)], {"from": ATTACKER, "to": DRAINER}, owner_spenders, set(),
                                lambda x: True, lambda x: x == DRAINER) is None
    # victim submitted the tx itself
    assert detectors.d3_confirm(by_tx[tx_hash(7)], {"from": victims[0], "to": DRAINER}, owner_spenders, set(),
                                lambda x: x == DRAINER, never_allowed)["victims"] == sorted(victims[1:])


def test_d3_window():
    day = 86400
    ev = [(1000, a(1)), (1000 + day // 2, a(2)), (1000 + day - 1, a(3))]
    assert detectors.window_hit(ev)
    assert not detectors.window_hit([(1000, a(1)), (1000 + 2 * day, a(2)), (1000 + 4 * day, a(3))])
    assert not detectors.window_hit([(1000, a(1)), (1001, a(1)), (1002, a(1))])      # same victim


def test_d4_pays_known_operator():
    tr, _ = parsed(transfer_log(tx_hash(1), TOKEN, a(50), OP, 5), transfer_log(tx_hash(2), TOKEN, a(51), a(77), 5),
                   transfer_log(tx_hash(3), TOKEN, OP, OP, 5))
    out = detectors.d4_candidates(tr, {OP}, never_allowed)
    assert [t["frm"] for t in out] == [a(50)]
    assert detectors.d4_candidates(tr, {OP}, lambda x: x == a(50)) == []


def test_d1_seed_activity():
    seeds = SeedSet([(DRAINER, None, "ss", "scamsniffer")])
    tr, ap = parsed(approval_log(tx_hash(1), TOKEN, VICTIM, DRAINER, 5), approval_log(tx_hash(2), TOKEN, VICTIM, DRAINER, 0),
                    transfer_log(tx_hash(3), TOKEN, VICTIM, DRAINER, 9), transfer_log(tx_hash(4), TOKEN, VICTIM, a(88), 9))
    ev, legs = detectors.d1_seed_activity("eth", tr, ap, seeds)
    assert [e["tx"] for e in ev] == [tx_hash(1), tx_hash(3)]       # revoke (0) ignored
    assert len(legs) == 1


def test_tier_assignment():
    t = detectors.assign_tier
    assert t({"seed"}, 1, True) == "T1"
    assert t({"split_pull"}, 3, True) == "T1"
    assert t({"split_pull", "family_match"}, 1, True) == "T1"
    assert t({"split_pull"}, 2, True) == "T2"
    assert t({"pays_known_operator"}, 0, True) == "T2"
    assert t({"family_match"}, 0, True) == "T2"
    assert t({"family_match"}, 0, False) == "T3"
    assert t({"multi_victim_pull"}, 5, True) == "T3"
    assert t({"eip7702_sweeper"}, 0, False) == "T3"
    assert t({"redflag_payable"}, 0, True) == "T3"
    assert t({"redflag_selectors"}, 0, False) == "T3"
    assert t(set(), 5, True) is None
    assert detectors.score_of({"split_pull"}, 3, 5000, True) == min(100, 45 + 15 + 5 + 5)
