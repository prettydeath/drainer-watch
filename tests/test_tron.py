"""TRON chain: base58, block / log parsing, rules T-1..T-8 on synthetic blocks, rollup tiers, head-first gaps, and a
regression on the real VerifyAccount runtimes (public fixtures) and the reference drain (private fixture, skipped when
absent)."""
import json
import os
from pathlib import Path

import pytest

from drainerwatch import bytecode, render, rollup, scan, tron_detectors as td
from drainerwatch.auth7702 import G, _mul, pub_to_address, sign
from drainerwatch.constants import TRON_USDT, UINT256_MAX
from drainerwatch.db import connect
from drainerwatch.prices import Prices
from drainerwatch.render import describe
from drainerwatch.seeds import SeedSet
from drainerwatch.tron import (TOPIC_APPROVAL_T, TOPIC_TRANSFER_T, TRON_ZERO, is_tron_addr, parse_block, parse_infos,
                               signer_of, to_base58, to_hex)
from drainerwatch.tron_scan import TronCtx, load_hijacked, process_tron_chunk
from drainerwatch.util import selector

KITS = Path(__file__).parent / "fixtures_kits"
PRIVATE = Path(__file__).parent / "backtest" / "private" / "tron_verify_account_ref.json"
SUN = 1_000_000
T0 = 1_800_000_000


def T(n):
    return to_base58("41" + f"{n:040x}")


def word(addr):
    return "0" * 24 + to_hex(addr)[2:]


def num(v):
    return f"{v:064x}"


OPERATOR, CONTRACT, VICTIM, BIG, SMALL = T(0xA1), T(0xC1), T(0xB1), T(0xD1), T(0xD2)


# ---------- raw TronGrid shapes ----------
def blk(n, txs, ts=None):
    return {"block_header": {"raw_data": {"number": n, "timestamp": (ts or T0 + 3 * n) * 1000}}, "transactions": txs}


def trig(h, frm, to, data, fee_limit=100 * SUN, call_value=0, ok=True, sig=None):
    v = {"owner_address": frm, "contract_address": to, "data": data}
    if call_value:
        v["call_value"] = call_value
    tx = {"txID": h, "raw_data": {"contract": [{"type": "TriggerSmartContract", "parameter": {"value": v}}],
                                  "fee_limit": fee_limit}, "ret": [{"contractRet": "SUCCESS" if ok else "REVERT"}]}
    if sig:
        tx["signature"] = [sig]
    return tx


def trx(h, frm, to, amount, sig=None):
    tx = {"txID": h, "raw_data": {"contract": [{"type": "TransferContract", "parameter": {
        "value": {"owner_address": frm, "to_address": to, "amount": amount}}}]}, "ret": [{"contractRet": "SUCCESS"}]}
    if sig:
        tx["signature"] = [sig]
    return tx


def apu(h, frm, owner_keys, threshold=1, actives=None):
    v = {"owner_address": frm, "owner": {"type": 0, "permission_name": "owner", "threshold": threshold,
                                         "keys": [{"address": a, "weight": w} for a, w in owner_keys]},
         "actives": actives or [{"type": 2, "permission_name": "active", "threshold": threshold,
                                 "keys": [{"address": a, "weight": w} for a, w in owner_keys]}]}
    return {"txID": h, "raw_data": {"contract": [{"type": "AccountPermissionUpdateContract", "parameter": {"value": v}}]},
            "ret": [{"contractRet": "SUCCESS"}]}


def tlog(token, frm, to, value):
    return {"address": to_hex(token)[2:], "topics": [TOPIC_TRANSFER_T, word(frm), word(to)], "data": num(value)}


def alog(token, owner, spender, value):
    return {"address": to_hex(token)[2:], "topics": [TOPIC_APPROVAL_T, word(owner), word(spender)], "data": num(value)}


def info(h, logs=(), fee=0):
    return {"id": h, "fee": fee, "receipt": {"result": "SUCCESS"}, "log": list(logs)}


def h(n):
    return f"{n:064x}"


SEL_VERIFY20 = selector("Verify20(address,address,address,uint256)")
SEL_INC = selector("increaseApproval(address,uint256)")
SEL_APPROVE = selector("approve(address,uint256)")


def verify20(token, frm, to, amount):
    return SEL_VERIFY20 + word(token) + word(frm) + word(to) + num(amount)


def fixture(i):
    return (KITS / f"verify_account_tron_{i}.hex").read_text().strip()


class FakeTronRpc:
    chain = "tron"

    def __init__(self, contracts=None, accounts=None):
        self.contracts = contracts or {}       # addr -> dict(runtime, origin, name)
        self.accounts = accounts or {}
        self.calls = self.limit_hits = self.errors = self.bytes = 0
        self._ts = {}

    def contract_info(self, addr):
        return self.contracts.get(addr)

    def account(self, addr):
        return self.accounts.get(addr, {})

    def get_code_many(self, addrs):
        return {a: "0x" + self.contracts[a]["runtime"] if a in self.contracts else "0x" for a in addrs}

    def eth_call_many(self, calls):
        out = []
        for _, data in calls:
            out.append("0x" + b"USDT".ljust(32, b"\0").hex() if data.startswith("0x95d89b41") else "0x" + num(6))
        return out

    def block_times(self, numbers):
        return {n: T0 + 3 * n for n in numbers}


def make_ctx(contracts=None, accounts=None, seeds=None):
    conn = connect(":memory:")
    return TronCtx(conn, FakeTronRpc(contracts, accounts), seeds or SeedSet(), {}, Prices(native={"TRX": 0.3}))


def run(ctx, *blocks_infos):
    for blocks, infos in blocks_infos:
        process_tron_chunk(ctx, blocks, infos)


def ev(ctx, type_):
    return [(r["address"], json.loads(r["detail"])) for r in ctx.conn.execute(
        "SELECT address,detail FROM evidence WHERE type=? ORDER BY id", (type_,))]


def tiers(ctx):
    rows = rollup.rollup(ctx.conn, SeedSet(), {})
    return {r["address"]: r for r in rows}


# ---------- addresses / parsing ----------
def test_base58_roundtrip_and_known_values():
    assert to_base58("41a614f803b6fd780986a42c78ec9c7f77e6ded13c") == TRON_USDT
    assert to_hex(TRON_USDT) == "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
    assert to_base58("a614f803b6fd780986a42c78ec9c7f77e6ded13c") == TRON_USDT        # bare 20-byte log address
    assert to_base58("0" * 24 + "a614f803b6fd780986a42c78ec9c7f77e6ded13c") == TRON_USDT   # topic word
    assert TRON_ZERO == "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"
    assert not is_tron_addr(TRON_USDT[:-1] + ("u" if TRON_USDT[-1] != "u" else "v"))  # checksum
    for n in (1, 0xFFFF, 2 ** 159):
        assert to_base58(to_hex(T(n))) == T(n)


def test_parse_block_and_infos():
    b = blk(10, [trig(h(1), VICTIM, TRON_USDT, SEL_INC + word(CONTRACT) + num(UINT256_MAX), fee_limit=150 * SUN),
                 trx(h(2), OPERATOR, VICTIM, 20 * SUN)])
    txs = parse_block(b)
    assert txs[0]["type"] == "TriggerSmartContract" and txs[0]["to"] == TRON_USDT and txs[0]["fee_limit"] == 150 * SUN
    assert txs[1]["amount"] == 20 * SUN and txs[1]["frm"] == OPERATOR
    tr, ap, meta = parse_infos([info(h(1), [alog(TRON_USDT, VICTIM, CONTRACT, UINT256_MAX),
                                            tlog(TRON_USDT, VICTIM, BIG, 5)], fee=7)], 10)
    assert ap[0]["owner"] == VICTIM and ap[0]["spender"] == CONTRACT and ap[0]["value"] == UINT256_MAX
    assert tr[0]["frm"] == VICTIM and tr[0]["to"] == BIG and tr[0]["token"] == TRON_USDT and meta[h(1)]["fee"] == 7


def test_signer_recovery():
    priv = 0xC0FFEE
    addr = to_base58(pub_to_address(_mul(priv, G))[2:])
    txid = h(0xABC)
    r, s, rec = sign(bytes.fromhex(txid), priv, 0x1234567)
    tx = dict(h=txid, sig=[f"{r:064x}{s:064x}{rec + 27:02x}"])
    assert signer_of(tx) == addr


# ---------- T-1 / T-2 bytecode on real runtimes ----------
@pytest.mark.parametrize("i", [1, 2, 3, 4, 5])
def test_verify_account_runtimes_classify(i):
    a = bytecode.analyze("0x" + fixture(i), tvm=True)
    assert a["kit"] == "verify_account"
    assert a["owner_gated_puller"] is True                       # R-A2: owner check, parametric transferFrom, no PUSH20
    assert {"5082dd12", "fc61dd23", "ea4418d9", "8da5cb5b"} <= set(a["selectors"])
    assert a["size"] == 2605 and "CALLTOKENVALUE" in a["tvm_ops"]


def test_tvm_calltoken_counts_as_call():
    # owner check (SLOAD CALLER EQ), PUSH4 transferFrom (not a dispatcher compare), CALLDATALOAD, CALLTOKEN instead of CALL
    disp = "63" + "11223344" + "14"                                     # PUSH4 sel EQ
    body = "6000" + "54" + "33" + "14" + "6000" + "35" + "63" + "23b872dd" + "50" + "d0"
    code = "0x" + disp + body
    assert not bytecode.owner_gated_puller(code)
    assert bytecode.owner_gated_puller(code, tvm=True)


# ---------- T-1 / T-4 / T-3: the VerifyAccount flow (synthetic, same shape as case A) ----------
def verify_account_flow(ctx_victims=1):
    contracts = {CONTRACT: dict(runtime=fixture(1), origin=OPERATOR, name="VerifyAccount")}
    ctx = make_ctx(contracts)
    steps = []
    for k in range(ctx_victims):
        v = T(0xB100 + k)
        n = 100 + 10 * k
        steps.append(([blk(n, [trx(h(1000 + k), OPERATOR, v, 20 * SUN)])], {n: [info(h(1000 + k))]}))
        steps.append(([blk(n + 1, [trig(h(2000 + k), v, TRON_USDT, SEL_INC + word(CONTRACT) + num(UINT256_MAX),
                                        fee_limit=150 * SUN)])],
                      {n + 1: [info(h(2000 + k), [alog(TRON_USDT, v, CONTRACT, UINT256_MAX)])]}))
        big, small = 29_495_060_000, 601_940_000
        steps.append(([blk(n + 5, [trig(h(3000 + k), OPERATOR, CONTRACT, verify20(TRON_USDT, v, BIG, big)),
                                   trig(h(4000 + k), OPERATOR, CONTRACT, verify20(TRON_USDT, v, SMALL, small))])],
                      {n + 5: [info(h(3000 + k), [tlog(TRON_USDT, v, BIG, big)]),
                               info(h(4000 + k), [tlog(TRON_USDT, v, SMALL, small)])]}))
    run(ctx, *steps)
    return ctx


def test_verify_account_flow_one_victim():
    ctx = verify_account_flow(1)
    kp = ev(ctx, "kit_pull")
    assert len(kp) == 2 and all(a == CONTRACT and d["kit"] == "verify_account" and d["caller_is_creator"] for a, d in kp)
    (subj, xs), = ev(ctx, "split_xtx")
    assert subj == CONTRACT and [r["wallet"] for r in xs["recipients"]] == [BIG, SMALL]
    assert [r["share"] for r in xs["recipients"]] == [0.98, 0.02]
    (f, pf), = ev(ctx, "prefund_approve")
    assert f == OPERATOR and pf["amount_trx"] == 20 and pf["spender_creator"] is True
    (s, ap), = ev(ctx, "tron_approval")
    assert s == CONTRACT and ap["kind"] == "increase_max" and ap["spender_kit"] == "verify_account"
    roles = {r["wallet"]: r["role"] for r in ctx.conn.execute("SELECT wallet,role FROM payouts WHERE drainer=?", (CONTRACT,))}
    assert roles == {BIG: "affiliate", SMALL: "operator", OPERATOR: "funder"}
    rows = tiers(ctx)
    assert rows[CONTRACT]["tier"] == "T1" and {"kit_pull", "kit_signature", "split_xtx"} <= set(rows[CONTRACT]["labels"])
    assert rows[OPERATOR]["tier"] == "T3" and "prefund_approve" in rows[OPERATOR]["labels"]
    assert rows[CONTRACT]["usd"] == pytest.approx(30097.0, abs=0.01)


def test_prefund_hub_three_victims_is_t2():
    rows = tiers(verify_account_flow(3))
    assert rows[OPERATOR]["tier"] == "T2" and "prefund_approve_multi" in rows[OPERATOR]["labels"]
    assert rows[CONTRACT]["victims"] == 3


def test_plain_contract_pull_not_flagged():
    other = T(0xE1)
    ctx = make_ctx({other: dict(runtime="6080604052" + "00" * 40, origin=OPERATOR, name="Router")})
    n = 50
    run(ctx, ([blk(n, [trig(h(1), OPERATOR, other, "deadbeef")])], {n: [info(h(1), [tlog(TRON_USDT, VICTIM, BIG, 10 ** 9)])]}))
    assert not ev(ctx, "kit_pull") and not tiers(ctx)


# ---------- T-3 approval fingerprints ----------
def approval_tx(n, sp, amount, fee_limit, sel=SEL_APPROVE, owner=VICTIM, hh=1):
    data = sel + word(sp) + ("" if amount is None else num(amount))
    return trig(h(hh), owner, TRON_USDT, data, fee_limit=fee_limit)


def test_kit_amount_with_kit_fee_limit_is_fingerprint():
    sp = T(0xF1)
    ctx = make_ctx(accounts={sp: {"create_time": (T0 - 86400) * 1000}})
    run(ctx, ([blk(10, [approval_tx(10, sp, 10 ** 46, 35 * SUN)])], {10: [info(h(1))]}))
    (a, d), = ev(ctx, "approval_fingerprint")
    assert a == sp and d["kit"] == "tron_1e46_fee35"
    assert tiers(ctx)[sp]["tier"] == "T1"


def test_kit_amount_other_fee_limit_is_t2():
    sp = T(0xF2)
    ctx = make_ctx()
    run(ctx, ([blk(10, [approval_tx(10, sp, 10 ** 46, 100 * SUN)])], {10: [info(h(1))]}))
    assert tiers(ctx)[sp]["tier"] == "T2" and "approval_kit_shape" in tiers(ctx)[sp]["labels"]


def test_approve_all_selector():
    sp = T(0xF3)
    ctx = make_ctx()
    run(ctx, ([blk(10, [trig(h(1), VICTIM, TRON_USDT, "daea85c5" + word(sp))])], {10: [info(h(1))]}))
    (a, d), = ev(ctx, "tron_approval")
    assert a == sp and d["kind"] == "approve_all"
    assert tiers(ctx)[sp]["tier"] == "T2"


def test_aml_exact_needs_the_bait_transfer():
    sp = T(0xF4)
    bal = 1234_567890
    ctx = make_ctx()
    run(ctx, ([blk(10, [approval_tx(10, sp, bal, 300 * SUN)])], {10: [info(h(1))]}))
    assert not ev(ctx, "tron_approval")                                   # approval alone: nothing
    run(ctx, ([blk(11, [trig(h(2), VICTIM, TRON_USDT, "a9059cbb" + word(sp) + num(0))])],
              {11: [info(h(2), [tlog(TRON_USDT, VICTIM, sp, 0)])]}))
    (a, d), = ev(ctx, "tron_approval")
    assert a == sp and d["kind"] == "aml_exact" and d["transfer_tx"] == h(2)
    assert tiers(ctx)[sp]["tier"] == "T2"


def test_aml_exact_three_victims_is_t1_and_pull_is_recorded():
    sp = T(0xF5)
    ctx = make_ctx()
    for k in range(3):
        v = T(0xB200 + k)
        run(ctx, ([blk(10 + k, [approval_tx(10, sp, 500 * SUN, 300 * SUN, owner=v, hh=10 + k),
                                trig(h(20 + k), v, TRON_USDT, "a9059cbb" + word(sp) + num(500 * SUN))])],
                  {10 + k: [info(h(10 + k)), info(h(20 + k), [tlog(TRON_USDT, v, sp, 500 * SUN)])]}))
    # the spender then pulls a fourth wallet's tokens with transferFrom (EOA spender pull after a kit approval)
    v4 = T(0xB2FF)
    run(ctx, ([blk(20, [trig(h(99), sp, TRON_USDT, "23b872dd" + word(v4) + word(sp) + num(7 * SUN))])],
              {20: [info(h(99), [tlog(TRON_USDT, v4, sp, 7 * SUN)])]}))
    assert ev(ctx, "eoa_spender_pull")[0][1]["victim"] == v4
    assert tiers(ctx)[sp]["tier"] == "T1"


def test_increase_max_to_old_eoa_ignored_fresh_eoa_t3():
    old, fresh = T(0xF6), T(0xF7)
    ctx = make_ctx(accounts={old: {"create_time": (T0 - 400 * 86400) * 1000}, fresh: {"create_time": (T0 - 86400) * 1000}})
    run(ctx, ([blk(10, [approval_tx(10, old, UINT256_MAX, 100 * SUN, sel=SEL_INC, hh=1),
                        approval_tx(10, fresh, UINT256_MAX, 100 * SUN, sel=SEL_INC, hh=2)])],
              {10: [info(h(1)), info(h(2))]}))
    assert [a for a, _ in ev(ctx, "tron_approval")] == [fresh]
    assert tiers(ctx)[fresh]["tier"] == "T3"


# ---------- T-5 Claimer ----------
def claimer_runtime():
    sels = [selector(n) for n in ("Multicall(address)", "Claim(address)", "getOwner()", "getBalance()")]
    return "".join("63" + s + "14" for s in sels) + "00"


def test_claimer_shape_t1():
    cl, recv = T(0xCC), T(0xCD)
    value = 80 * SUN * 10                                      # balance before 1000 TRX -> 800 TRX taken, 200 left
    ctx = make_ctx({cl: dict(runtime=claimer_runtime(), origin=recv, name="Claimer")},
                   {VICTIM: {"balance": 200 * SUN, "latest_opration_time": (T0 + 30) * 1000}})
    run(ctx, ([blk(10, [trig(h(1), VICTIM, cl, selector("Multicall(address)") + word(recv), call_value=value)])],
              {10: [info(h(1))]}))
    (a, d), = ev(ctx, "bait_payable")
    assert a == cl and d["claimer_shape"] is True and d["customer"] == recv and d["unit"] == "sun"
    r = tiers(ctx)[cl]
    assert r["tier"] == "T1" and {"claimer_split", "kit_signature", "bait_payable"} <= set(r["labels"])
    assert "TRX to bait function" in describe("bait_payable", d)


def test_claimer_other_amount_is_bait_t2():
    cl, recv = T(0xCE), T(0xCF)
    ctx = make_ctx({cl: dict(runtime=claimer_runtime(), origin=recv, name="Claimer")},
                   {VICTIM: {"balance": 900 * SUN, "latest_opration_time": (T0 + 30) * 1000}})
    run(ctx, ([blk(10, [trig(h(1), VICTIM, cl, selector("Multicall(address)") + word(recv), call_value=100 * SUN)])],
              {10: [info(h(1))]}))
    assert ev(ctx, "bait_payable")[0][1]["claimer_shape"] is False
    assert tiers(ctx)[cl]["tier"] == "T2"


def test_claimer_shape_math():
    assert td.claimer_shape(800 * SUN, 200 * SUN) is True                  # 0.8 of 1000
    assert td.claimer_shape(50 * SUN, 50 * SUN) is True                    # 100 TRX: bal - 50 < 0.8 bal
    assert td.claimer_shape(10 * SUN, 500 * SUN) is False
    assert td.claimer_shape(10 * SUN, None) is None


# ---------- T-6 permission takeover ----------
def keypair(priv):
    return priv, to_base58(pub_to_address(_mul(priv, G))[2:])


def signed(txid, priv):
    r, s, rec = sign(bytes.fromhex(txid), priv, 0x777 + priv)
    return f"{r:064x}{s:064x}{rec + 27:02x}"


def test_perm_hijack_then_signed_drain_t1():
    priv, ctrl = keypair(0xBEEF)
    acc = {VICTIM: {"create_time": (T0 - 90 * 86400) * 1000}}          # ctrl has no account: no history
    ctx = make_ctx(accounts=acc)
    load_hijacked(ctx)
    run(ctx, ([blk(10, [apu(h(1), VICTIM, [(ctrl, 1)])])], {10: [info(h(1))]}))
    (a, d), = ev(ctx, "perm_hijack")
    assert a == ctrl and d["owner_lost"] and d["fresh_keys"] == [ctrl] and d["age_days"] >= 89
    assert tiers(ctx)[ctrl]["tier"] == "T3"
    # outflow signed by the controller key (Permission_id 2) -> T1
    txid = h(2)
    run(ctx, ([blk(20, [trx(txid, VICTIM, BIG, 300 * SUN, sig=signed(txid, priv))])], {20: [info(txid)]}))
    (a2, d2), = ev(ctx, "perm_hijack_drain")
    assert a2 == ctrl and d2["victim"] == VICTIM and d2["amount_trx"] == 300
    assert tiers(ctx)[ctrl]["tier"] == "T1"


def test_perm_change_noise_ignored():
    _, ctrl = keypair(0xF00D)
    young = {VICTIM: {"create_time": (T0 - 3600) * 1000}}
    ctx = make_ctx(accounts=young)
    run(ctx, ([blk(10, [apu(h(1), VICTIM, [(ctrl, 1)])])], {10: [info(h(1))]}))          # same-day setup
    assert not ev(ctx, "perm_hijack")
    ctx = make_ctx(accounts={VICTIM: {"create_time": (T0 - 90 * 86400) * 1000}})
    run(ctx, ([blk(10, [apu(h(1), VICTIM, [(VICTIM, 1), (ctrl, 1)])])], {10: [info(h(1))]}))  # own key still enough
    assert not ev(ctx, "perm_hijack")


def test_perm_controller_many_accounts_tiers():
    lb = {"perm_hijack", "perm_hijack_multi"}
    from drainerwatch.detectors import assign_tier
    assert assign_tier({"perm_hijack"}, 1, True) == "T3"
    assert assign_tier(lb, 3, True) == "T2"
    assert assign_tier(lb, 50, True) == "T2"                    # count alone never T1: needs a signed drain


def test_perm_shapes():
    acc, k1, k2 = VICTIM, T(0x11), T(0x12)
    org = apu(h(1), acc, [(k1, 1), (k2, 1)], threshold=2)                  # two foreign keys must co-sign: org multisig
    assert td.perm_change(parse_block(blk(1, [org]))[0]) is None
    lock = apu(h(2), acc, [(acc, 1), (k1, 1)], threshold=2)                 # victim key kept, attacker completes it
    assert td.perm_change(parse_block(blk(1, [lock]))[0])["shape"] == "cosign_lock"
    single = apu(h(3), acc, [(k1, 1)], threshold=1)
    assert td.perm_change(parse_block(blk(1, [single]))[0])["shape"] == "single_key"


def test_prefund_same_block_is_relayer():
    contracts = {CONTRACT: dict(runtime=fixture(1), origin=OPERATOR, name="VerifyAccount")}
    ctx = make_ctx(contracts)
    run(ctx, ([blk(10, [trx(h(1), OPERATOR, VICTIM, 20 * SUN),
                        trig(h(2), VICTIM, TRON_USDT, SEL_INC + word(CONTRACT) + num(UINT256_MAX))])],
              {10: [info(h(1)), info(h(2))]}))
    assert not ev(ctx, "prefund_approve")


def test_large_trx_after_pull_is_not_a_fee():
    spender, to = T(0x7E), T(0x7F)
    ctx = make_ctx()
    run(ctx, ([blk(10, [trig(h(1), spender, TRON_USDT, "23b872dd" + word(VICTIM) + word(BIG) + num(9 * SUN)),
                        trx(h(2), spender, to, 500 * SUN)])],
              {10: [info(h(1), [tlog(TRON_USDT, VICTIM, BIG, 9 * SUN)]), info(h(2))]}))
    assert not ev(ctx, "fixed_fee")


def test_tron_split_without_kit_capped_t3():
    splitter = T(0x80)
    ctx = make_ctx({splitter: dict(runtime="6000", origin=None, name="Forwarder")})
    run(ctx, ([blk(10, [trig(h(1), OPERATOR, splitter, "12345678")])],
              {10: [info(h(1), [tlog(TRON_USDT, VICTIM, BIG, 70 * SUN), tlog(TRON_USDT, VICTIM, SMALL, 30 * SUN)])]}))
    assert ev(ctx, "split_pull")
    r = tiers(ctx)[splitter]
    assert r["tier"] == "T3" and "tron_split_capped" in r["labels"]


# ---------- T-7 fixed fee ----------
def test_fixed_fee_after_pulls():
    spender, fee_to = T(0x5E), T(0x5F)
    ctx = make_ctx()
    for k in range(3):
        v = T(0xB300 + k)
        n = 10 + 5 * k
        run(ctx, ([blk(n, [trig(h(10 + k), spender, TRON_USDT, "23b872dd" + word(v) + word(BIG) + num(9 * SUN)),
                           trx(h(20 + k), spender, fee_to, 30 * SUN)])],
                  {n: [info(h(10 + k), [tlog(TRON_USDT, v, BIG, 9 * SUN)]), info(h(20 + k))]}))
    fees = ev(ctx, "fixed_fee")
    assert len(fees) == 3 and all(a == fee_to and d["amount_trx"] == 30 for a, d in fees)
    r = tiers(ctx)[fee_to]
    assert r["tier"] == "T2" and {"fixed_fee", "fixed_fee_multi"} <= set(r["labels"])


def test_single_fee_not_labelled():
    spender, fee_to = T(0x6E), T(0x6F)
    ctx = make_ctx()
    run(ctx, ([blk(10, [trig(h(1), spender, TRON_USDT, "23b872dd" + word(VICTIM) + word(BIG) + num(9 * SUN)),
                        trx(h(2), spender, fee_to, 30 * SUN)])],
              {10: [info(h(1), [tlog(TRON_USDT, VICTIM, BIG, 9 * SUN)]), info(h(2))]}))
    assert ev(ctx, "fixed_fee") and fee_to not in tiers(ctx)


# ---------- T-8 poisoning ----------
def test_zero_value_poisoning_is_t3_only():
    poisoner = T(0x70)
    ctx = make_ctx({poisoner: dict(runtime="6000", origin=None, name="")})
    legs = [tlog(TRON_USDT, T(0xB400 + k), T(0xB500 + k), 0) for k in range(3)]
    run(ctx, ([blk(10, [trig(h(1), OPERATOR, poisoner, "12345678")])], {10: [info(h(1), legs)]}))
    (a, d), = ev(ctx, "zero_transfer_spoof")
    assert a == poisoner and d["legs"] == 3
    r = tiers(ctx)[poisoner]
    assert r["tier"] == "T3" and r["victims"] == 0 and r["drains"] == 0


# ---------- allowlist / labels ----------
def test_allowlisted_and_labelled_spenders_skipped(tmp_path, monkeypatch):
    sp = T(0xF8)
    ctx = make_ctx()
    ctx.labels = {("tron", sp): ("SomeExchange", "exchange", "hot wallet")}
    run(ctx, ([blk(10, [approval_tx(10, sp, 10 ** 46, 100 * SUN)])], {10: [info(h(1))]}))
    assert not ev(ctx, "tron_approval")


# ---------- head-first gaps ----------
def test_plan_range_jumps_to_head_and_records_gap():
    conn = connect(":memory:")
    from drainerwatch.db import meta_set
    meta_set(conn, "cursor:tron", 1000)
    a, b = scan.plan_range(conn, "tron", 5002, 300, now=T0)
    assert (a, b) == (4701, 5000)
    assert scan.load_gaps(conn, "tron") == [{"from": 1001, "to": 4700, "at": T0}]
    meta_set(conn, "cursor:tron", 5000)
    assert scan.plan_range(conn, "tron", 5102, 300) == (5001, 5100)        # keeping up: no new gap
    assert len(scan.load_gaps(conn, "tron")) == 1
    meta_set(conn, "head:tron", 5102)
    p = render.build_payload(conn, now=T0)
    assert p["chains"]["tron"]["gap_blocks"] == 3700 and p["chains"]["tron"]["tx_path"] == "transaction"
    assert p["chains"]["tron"]["gaps"][0]["from"] == 1001


def test_plan_range_fresh_db_and_cap():
    conn = connect(":memory:")
    assert scan.plan_range(conn, "eth", 10_000, 100) == (9700, 9799)
    from drainerwatch.constants import MAX_GAPS
    from drainerwatch.db import meta_set
    for k in range(MAX_GAPS + 5):
        meta_set(conn, "cursor:eth", k * 1000)
        scan.plan_range(conn, "eth", k * 1000 + 600, 100)
    assert len(scan.load_gaps(conn, "eth")) == MAX_GAPS


def test_describe_tron_types():
    for t, d in (("kit_pull", dict(kit="verify_account", caller_is_creator=True)), ("tron_approval", dict(kind="aml_exact")),
                 ("prefund_approve", dict(amount_trx=20)), ("perm_hijack", dict(owner_lost=True, controllers=["x"])),
                 ("perm_hijack_drain", dict(amount_trx=1)), ("fixed_fee", dict(amount_trx=30)),
                 ("zero_transfer_spoof", dict(legs=3, victims=3))):
        assert not describe(t, d).startswith("{")


def test_seed_csv_and_allowlist_accept_base58(tmp_path):
    from drainerwatch.seeds import load_allowlist, read_local_csv
    p = tmp_path / "s.csv"
    p.write_text(f"address,chain,label\n{CONTRACT},tron,x\n{CONTRACT.lower()},tron,bad\n", encoding="utf-8")
    assert read_local_csv(p) == [(CONTRACT, "tron", "x", "local")]
    q = tmp_path / "a.csv"
    q.write_text(f"chain,address,note\ntron,{BIG},n\n", encoding="utf-8")
    assert load_allowlist("tron", q) == {BIG} and load_allowlist("eth", q) == set()


# ---------- real-data regression (private fixture: tests/backtest/private, gitignored) ----------
@pytest.mark.skipif(not PRIVATE.exists(), reason="private reference fixture not present")
def test_reference_drain_real_data():
    items = json.loads(PRIVATE.read_text(encoding="utf-8"))
    by_block = {}
    for it in items:
        n = it["info"]["blockNumber"]
        by_block.setdefault(n, ([], []))
        by_block[n][0].append(it["tx"])
        by_block[n][1].append(it["info"])
    first = items[2]["tx"]["raw_data"]["contract"][0]["parameter"]["value"]
    contract, operator = first["contract_address"], first["owner_address"]
    contracts = {contract: dict(runtime=fixture(1), origin=operator, name="VerifyAccount")}
    ctx = make_ctx(contracts)
    ctx.rpc.block_times = lambda ns: {n: None for n in ns}
    for n in sorted(by_block):
        txs, infos = by_block[n]
        ts = infos[0]["blockTimeStamp"] // 1000
        process_tron_chunk(ctx, [blk(n, txs, ts=ts)], {n: infos})
    (subj, xs), = ev(ctx, "split_xtx")
    assert subj == contract
    shares = [r["share"] for r in xs["recipients"]]
    assert shares == [0.98, 0.02]
    assert {d["kit"] for _, d in ev(ctx, "kit_pull")} == {"verify_account"}
    (f, pf), = ev(ctx, "prefund_approve")
    assert f == operator and pf["amount_trx"] == 20 and 0 < pf["sec_before"] < 600
    rows = tiers(ctx)
    assert rows[contract]["tier"] == "T1" and rows[contract]["usd"] == pytest.approx(30097.0, abs=1)
    os.environ.pop("_", None)


@pytest.mark.parametrize("name,kit", [("buytron_swap_trx_tron.hex", "buytron_swap_trx"),
                                      ("buytron_swap_proxy_tron.hex", "buytron_swap_proxy")])
def test_buytron_runtimes_classify(name, kit):
    a = bytecode.analyze("0x" + (KITS / name).read_text().strip(), tvm=True)
    assert a["kit"] == kit


def test_buytron_pull_is_t1():
    c, admin = T(0x9A), T(0x9B)
    ctx = make_ctx({c: dict(runtime=(KITS / "buytron_swap_trx_tron.hex").read_text().strip(), origin=admin, name="SwapTRX")})
    run(ctx, ([blk(10, [trig(h(1), admin, c, selector("pullFunds(address,address,uint256)") + word(VICTIM) + word(BIG)
                             + num(50 * SUN))])], {10: [info(h(1), [tlog(TRON_USDT, VICTIM, BIG, 50 * SUN)])]}))
    assert tiers(ctx)[c]["tier"] == "T1"


def test_missing_tx_info_never_advances_past_the_block(monkeypatch):
    from drainerwatch import tron_scan
    from drainerwatch.db import meta_get

    class R(FakeTronRpc):
        keyless = True

        def block_number(self):
            return 1000

        def blocks(self, a, b):
            return [blk(n, []) for n in range(a, b + 1)]

        def tx_infos(self, ns):
            return {n: (None if n == 945 else []) for n in ns}

    conn = connect(":memory:")
    from drainerwatch.db import meta_set
    meta_set(conn, "cursor:tron", 900)
    st = tron_scan.scan_tron(conn, SeedSet(), {}, Prices(native={}), rpc=R(), chunk=20)
    assert st["start"] == 1000 - 2 - 60 + 1                     # keyless window is 60 blocks (gap 901-938 recorded)
    assert meta_get(conn, "cursor:tron") == "944" and st["info_missing"] == 1
    p = render.build_payload(conn)
    assert "API key" in p["chains"]["tron"]["note"]
