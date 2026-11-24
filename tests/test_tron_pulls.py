"""TRON generic pulls (EVM D8 / D3 analogues): EOA signer transferFrom, contract pulls of non-signers, guards."""
from drainerwatch import detectors
from tests.test_tron import (BIG, SEL_INC, SUN, T, T0, TRON_USDT, blk, ev, h, info, make_ctx, num, run, tiers, tlog, trig,
                             trx, word)
from drainerwatch.constants import UINT256_MAX

SIGNER = T(0x5161)


def pull_tx(n, k, signer=SIGNER, victim=None, to=BIG, amount=50 * SUN + 123_457):
    v = victim or T(0xB300 + k)
    return ([blk(n, [trig(h(100 + k), signer, TRON_USDT, "23b872dd" + word(v) + word(to) + num(amount))])],
            {n: [info(h(100 + k), [tlog(TRON_USDT, v, to, amount)])]})


def test_eoa_signer_pulls_three_victims_t2():
    ctx = make_ctx()
    run(ctx, pull_tx(10, 0))
    assert tiers(ctx)[SIGNER]["tier"] == "T3" and tiers(ctx)[SIGNER]["labels"] == ["tron_eoa_pull"]
    run(ctx, pull_tx(11, 1))
    run(ctx, pull_tx(12, 2))
    r = tiers(ctx)[SIGNER]
    assert r["tier"] == "T2" and "tron_eoa_pull_multi" in r["labels"] and r["victims"] == 3
    (_, d), *_ = ev(ctx, "tron_eoa_pull")
    assert d["recipient"] == BIG


def test_max_approval_alone_does_not_make_t1():
    ctx = make_ctx(accounts={SIGNER: {"create_time": (T0 - 400 * 86400) * 1000}})      # an old account: increaseApproval MAX is not T-3 evidence
    for k in range(3):
        v = T(0xB400 + k)
        run(ctx, ([blk(20 + k, [trig(h(200 + k), v, TRON_USDT, SEL_INC + word(SIGNER) + num(UINT256_MAX))])],
                  {20 + k: [info(h(200 + k))]}))
        run(ctx, pull_tx(30 + k, 10 + k, victim=v))
    r = tiers(ctx)[SIGNER]
    assert r["tier"] == "T2" and "tron_max_approval" in r["labels"]
    t = detectors.assign_tier
    assert t({"tron_eoa_pull", "tron_eoa_pull_multi", "tron_max_approval", "fixed_fee"}, 3, True) == "T1"
    assert t({"tron_eoa_pull", "tron_eoa_pull_multi", "fixed_fee"}, 3, True) == "T2"
    assert t({"tron_contract_pull"}, 3, True) == "T3"
    assert t({"tron_contract_pull", "owner_gated_puller"}, 3, True) == "T2"


def test_guards_contract_victim_service_and_own_deposit_wallet():
    c = T(0xC0DE)
    ctx = make_ctx({c: dict(runtime="6080604052" + "00" * 40, origin=SIGNER, name="X")})
    run(ctx, pull_tx(10, 0, victim=c))                       # the "victim" is a contract
    assert not ev(ctx, "tron_eoa_pull")
    ctx = make_ctx()
    ctx.signer_n[SIGNER] = 10_000                            # a high-volume service signer
    run(ctx, pull_tx(10, 0))
    assert not ev(ctx, "tron_eoa_pull")
    ctx = make_ctx()
    v = T(0xB500)
    for k in range(2):                                       # the signer funds its own deposit wallet repeatedly
        run(ctx, ([blk(5 + k, [trx(h(50 + k), SIGNER, v, 20 * SUN)])], {5 + k: [info(h(50 + k))]}))
    run(ctx, pull_tx(10, 0, victim=v))
    assert not ev(ctx, "tron_eoa_pull")


def test_contract_pulling_three_non_signers_is_t3():
    c, op = T(0xC1C1), T(0xA9)
    ctx = make_ctx({c: dict(runtime="6080604052" + "00" * 40, origin=op, name="Gateway")})
    for k in range(3):
        v = T(0xB600 + k)
        run(ctx, ([blk(40 + k, [trig(h(400 + k), op, c, "deadbeef")])],
                  {40 + k: [info(h(400 + k), [tlog(TRON_USDT, v, BIG, 9 * SUN)])]}))
    r = tiers(ctx)[c]
    assert r["tier"] == "T3" and r["labels"] == ["tron_contract_pull"]


def test_whole_amount_pulls_are_service_payments():
    ctx = make_ctx()
    for k in range(3):
        run(ctx, pull_tx(10 + k, k, amount=1000 * SUN))
    r = tiers(ctx)[SIGNER]
    assert r["tier"] == "T3" and "tron_eoa_pull_multi" not in r["labels"]
