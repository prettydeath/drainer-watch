"""kit notes K1-K14 rules K1-K9, K12-K14: MS_NEW bait, generated bait, pass-through bait, millisecond deadlines,
one-shot EOA spenders + hubs, kit Deposit, EIP-5792 batch approvals, kit-amount router swaps, OwnerCollector,
EIP-7702 operators, cross-chain twins."""
from pathlib import Path

from drainerwatch import bytecode, detectors, enrich, rollup, scan
from drainerwatch.constants import (GEN_BAIT_SKELETON, KIT_APPROVAL_AMOUNTS, MS_NEW_SELECTORS, ONESHOT_RETURN_GAS,
                                    UINT256_MAX)
from drainerwatch.db import add_evidence
from drainerwatch.render import build_payload, describe
from drainerwatch.rpc import split_receipts
from drainerwatch.seeds import SeedSet
from drainerwatch.util import keccak, selector
from tests.helpers import FakeRpc, a, approval_log, make_ctx, transfer_log, tx_hash
from tests.test_kits import BlockRpc, block, w

KITS = Path(__file__).parent / "fixtures_kits"
OC = "0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
OC_OWNER = "0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
OC_VICTIM = "0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
ROUTER02 = "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45"
KIT_AMOUNT = next(iter(KIT_APPROVAL_AMOUNTS))
CODE = "0x" + "60806040" * 40
V = lambda i: a(0xABC000 + i)  # noqa: E731
TS0 = 1_800_000_000


def oc_code():
    return (KITS / "owner_collector_eth.hex").read_text().strip()


def dispatcher(sels, tail=""):
    """Synthetic runtime: PUSH4 <sel> EQ PUSH2 JUMPI per selector (the solc dispatcher shape selectors_of() reads)."""
    return "0x6080604052" + "".join("8063" + s + "14610000" + "57" for s in sels) + tail + "00"


def tx(h, frm, to, inp="0x", value=0, nonce=5, gas=60_000):
    return {"hash": h, "type": "0x2", "from": frm, "to": to, "value": hex(value), "input": inp, "nonce": hex(nonce),
            "gas": hex(gas)}


def meta(txs, blocks):
    return {t["hash"]: {"from": t["from"], "to": t["to"], "block": blocks[t["hash"]], "created": None, "status": 1}
            for t in txs}


class KitRpc(BlockRpc):
    """BlockRpc + archive balances + storage reads."""

    def __init__(self, blocks=(), balances=None, storage=None, **kw):
        super().__init__(blocks, **kw)
        self.bal, self.storage = balances or {}, storage or {}

    def balances(self, pairs):
        return {p: self.bal.get(p) for p in pairs}

    def storage_many(self, pairs):
        return {p: self.storage.get(p) for p in pairs}


def run_blocks(blocks_txs, logs=(), codes=None, rpc_cls=KitRpc, **kw):
    """blocks_txs: {block: [tx]} -> ctx after process_chunk + eth_block_pass over the whole range."""
    lo, hi = min(blocks_txs), max(blocks_txs)
    bl = [block(n, blocks_txs.get(n, [])) for n in range(lo, hi + 1)]
    rpc = rpc_cls(bl, codes=codes or {}, symbols={USDT: ("USDT", 6), WETH: ("WETH", 18)}, **kw)
    ctx = make_ctx(rpc)
    txs = [t for ts in blocks_txs.values() for t in ts]
    m = meta(txs, {t["hash"]: n for n, ts in blocks_txs.items() for t in ts})
    scan.process_chunk(ctx, lo, hi, list(logs), txmeta=m)
    scan.eth_block_pass(ctx, lo, hi, txmeta=m)
    return ctx, {r["address"]: r for r in rollup.rollup(ctx.conn, SeedSet(), {})}


# ---------- K1 MS_NEW ----------
MS_NEW_BAITS = [selector(f"{n}(address,address,address,uint8,bool)") for n in ("Claim", "Deposit", "Connect")]
MS_NEW_CODE = dispatcher(MS_NEW_BAITS + [selector("changePercentage(uint8)"), selector("claimSalary()")])
MSN = a(0x5E5E5E)


def ms_new_input(name, dep, handler, keeper, pct=10, cb=0):
    return "0x" + selector(f"{name}(address,address,address,uint8,bool)") + w(dep) + w(handler) + w(keeper) + w(pct) + w(cb)


def test_ms_new_kit_family_and_decode():
    assert bytecode.analyze(MS_NEW_CODE)["kit"] == "ms_new"
    assert bytecode.kit_family(MS_NEW_BAITS[:2] + [selector("changePercentage(uint8)"), selector("claimSalary()")]) is None
    assert bytecode.kit_family(MS_NEW_BAITS + [selector("setReceiver(address)")]) is None
    assert len(MS_NEW_SELECTORS) == 19 and "38928522" in MS_NEW_SELECTORS and "c968b5f6" in MS_NEW_SELECTORS
    d = detectors.decode_ms_new(ms_new_input("Claim", V(1), a(0xC1), a(0xC2), 10))
    assert (d["depositer"], d["handler"], d["keeper"], d["percent"], d["cashback"]) == (V(1), a(0xC1), a(0xC2), 10, False)
    assert detectors.decode_ms_new(ms_new_input("Claim", V(1), a(0xC1), a(0xC2), 100)) is None      # percent > 99
    assert detectors.decode_ms_new(ms_new_input("Claim", V(1), a(0xC1), a(0xC2), 10, 2)) is None    # not a bool
    assert detectors.decode_ms_new(ms_new_input("Claim", V(1), a(0xC1), a(0xC2))[:-64]) is None     # short calldata
    bad = "0x" + selector("Claim(address,address,address,uint8,bool)") + "f" * 64 + w(a(0xC1)) * 4
    assert detectors.decode_ms_new(bad) is None


def _ms_new_run(victims, handler=a(0xC1C1C1), keeper=a(0xC2C2C2)):
    txs = [tx(tx_hash(10 + i), v, MSN, ms_new_input("Claim", v, handler, keeper), 10 ** 17) for i, v in enumerate(victims)]
    return run_blocks({100: txs}, codes={MSN: MS_NEW_CODE})


def test_ms_new_bait_roles_and_tiers():
    ctx, rows = _ms_new_run([V(1)])
    r = rows[MSN]
    assert r["tier"] == "T2" and r["family"] == "ms_new" and "bait_payable" in r["labels"]
    roles = dict(ctx.conn.execute("SELECT wallet, role FROM payouts WHERE drainer=?", (MSN,)).fetchall())
    assert roles == {a(0xC1C1C1): "customer", a(0xC2C2C2): "worker"}
    assert ctx.conn.execute("SELECT recipient FROM drains").fetchone()[0] == a(0xC1C1C1)
    _, rows = _ms_new_run([V(1), V(2), V(3)])
    assert rows[MSN]["tier"] == "T1" and rows[MSN]["victims"] == 3
    _, rows = _ms_new_run([V(1)], handler=V(1))                     # handler == sender: no customer attribution
    assert "bait_payable" not in rows[MSN]["labels"] and "redflag_payable" in rows[MSN]["labels"]


# ---------- K6 kit Deposit ----------
def _deposit(nonce=1, gas=100_000, balance=10 ** 18, value=98 * 10 ** 16, code=MS_NEW_CODE):
    dep = V(7)
    t = tx(tx_hash(30), dep, MSN, ms_new_input("Deposit", dep, a(0xC1C1C1), a(0xC2C2C2)), value, nonce=nonce, gas=gas)
    return run_blocks({100: [t]}, codes={MSN: code}, balances={(dep, 99): balance})


def test_k6_kit_deposit():
    ctx, rows = _deposit()
    assert {"kit_deposit", "bait_payable"} <= set(rows[MSN]["labels"])
    d = ctx.conn.execute("SELECT detail FROM evidence WHERE type='kit_deposit'").fetchone()[0]
    assert '"balance_share": 0.98' in d and '"gas_limit": 100000' in d
    for kw in (dict(nonce=3), dict(gas=120_000), dict(value=10 ** 17)):      # older EOA / other gas / partial amount
        _, rows = _deposit(**kw)
        assert "kit_deposit" not in rows[MSN]["labels"], kw
    _, rows = _deposit(code=CODE)                                            # proxy (selector not in dispatcher): K6 alone
    assert rows[MSN]["tier"] == "T2" and "kit_deposit" in rows[MSN]["labels"]


# ---------- K2 generated bait ----------
def gen_code(sel=selector("Claim()"), stipends=2, size=894, extra=""):
    body = "6080604052" + "8063" + sel + "14610000" + "57" + "6108fcf1" * stipends + "6064" + extra
    return "0x" + body + "5b" * (size - len(body) // 2)


def test_generated_bait_traits_and_exact_hash(monkeypatch):
    info = bytecode.analyze(gen_code())
    assert info["kit"] == "ms_generated" and info["kit_exact"] is None and info["size"] == 894
    assert bytecode.analyze(gen_code(stipends=1))["kit"] is None                     # one transfer only
    assert bytecode.analyze(gen_code(size=700))["kit"] is None                       # wrong size
    assert bytecode.analyze(gen_code(sel=selector("claim()")))["kit"] is None        # not a kit name
    assert bytecode.analyze(gen_code(extra="63" + selector("Swap()") + "50"))["kit"] is None   # two PUSH4
    assert bytecode.analyze(gen_code(extra="600055"))["kit"] is None                 # SSTORE in the runtime
    assert len(GEN_BAIT_SKELETON) == 64
    code = gen_code(stipends=1)                                                      # traits fail, exact hash wins
    h = "0x" + keccak(bytes.fromhex(code[2:])).hex()
    monkeypatch.setitem(bytecode.GEN_BAIT_RUNTIME_KECCAK, h, "Claim()")
    info = bytecode.analyze(code)
    assert info["kit"] == "ms_generated" and info["kit_exact"] == "Claim()"


class CreateRpc(KitRpc):
    def __init__(self, blocks=(), created=None, **kw):
        super().__init__(blocks, **kw)
        self.created = created or {}


def test_generated_bait_behaviour_receivers_fresh_back_transfer():
    gen, dep, main, fee, wallet = a(0x6E6E), a(0xDE01), a(0xAA01), a(0xFEE1), a(0xBAC0)
    slot2 = int(fee, 16) | (10 << 160) | (1 << 168)
    create = {"hash": tx_hash(40), "type": "0x2", "from": dep, "to": None, "value": "0x0", "input": "0x60", "nonce": "0x0",
              "gas": hex(300_000)}
    back = tx(tx_hash(41), dep, wallet, "0x", 5 * 10 ** 16, gas=21_000)
    victim = tx(tx_hash(42), V(1), gen, "0x" + selector("Claim()"), 10 ** 18)
    bl = {100: [create], 101: [back], 105: [victim]}
    blocks = [block(n, bl.get(n, [])) for n in range(100, 106)]
    rpc = KitRpc(blocks, codes={gen: gen_code()}, storage={(gen, 1): int(main, 16), (gen, 2): slot2},
                 symbols={USDT: ("USDT", 6)})
    ctx = make_ctx(rpc)
    m = {t["hash"]: {"from": t["from"], "to": t["to"], "block": n, "created": gen if t is create else None, "status": 1}
         for n, ts in bl.items() for t in ts}
    scan.process_chunk(ctx, 100, 105, [], txmeta=m)
    scan.eth_block_pass(ctx, 100, 105, txmeta=m)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["address"] == gen and r["family"] == "ms_generated" and r["tier"] == "T2"
    assert {"bait_payable", "gen_back_transfer", "kit_signature"} <= set(r["labels"])
    roles = dict(ctx.conn.execute("SELECT wallet, role FROM payouts").fetchall())
    assert roles == {main: "customer", fee: "kit_fee", wallet: "kit_wallet"}
    import json
    d = json.loads(ctx.conn.execute("SELECT detail FROM evidence WHERE type='bait_payable'").fetchone()[0])
    assert d["fee_percent"] == 10 and d["fresh"] and d["created_sec_before"] == 5 and d["uses"] == 1
    assert "generated bait Claim()" in describe("bait_payable", d)


# ---------- K3 pass-through ----------
PT_SELS = [selector("Claim(address)"), selector("getOwner()"), selector("getBalance()")]


def test_passthrough_variant_and_balance_neutral():
    assert bytecode.analyze(dispatcher(PT_SELS))["ms_variant"] == "passthrough"
    assert bytecode.analyze(dispatcher(PT_SELS, tail="600055"))["ms_variant"] == "multitenant"
    assert bytecode.analyze(dispatcher(PT_SELS))["kit"] == "ms_drainer"
    pt = a(0x9797)
    t = tx(tx_hash(50), V(1), pt, "0x" + selector("Claim(address)") + w(a(0xC1C1C1)), 10 ** 17)
    ctx, rows = run_blocks({100: [t]}, codes={pt: dispatcher(PT_SELS)}, balances={(pt, 99): 0, (pt, 100): 0})
    import json
    d = json.loads(ctx.conn.execute("SELECT detail FROM evidence WHERE type='bait_payable'").fetchone()[0])
    assert d["passthrough"] is True and d["balance_neutral"] is True and rows[pt]["tier"] == "T2"
    assert "pass-through" in describe("bait_payable", d)


# ---------- K4 millisecond deadlines ----------
MS = 1_800_000_000_000 + 30_758_400_000


def permit2612(owner, spender, deadline):
    return "0x" + selector("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)") + w(owner) + w(spender) \
        + w(10 ** 6) + w(deadline) + w(27) + w(1) + w(2)


def permit_dai(owner, spender, expiry):
    return "0x" + selector("permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)") + w(owner) + w(spender) \
        + w(0) + w(expiry) + w(1) + w(27) + w(1) + w(2)


def permit2_single(owner, token, spender, expiration, sig_deadline):
    sig = "11" * 65
    return ("0x" + selector("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)") + w(owner)
            + w(token) + w(10 ** 6) + w(expiration) + w(0) + w(spender) + w(sig_deadline) + w(0x100) + w(65)
            + sig + "0" * 62)


def permit2_batch(owner, tokens, spender, expiration, sig_deadline):
    n = len(tokens)
    details = w(n) + "".join(w(t) + w(10 ** 6) + w(expiration) + w(0) for t in tokens)
    struct = w(0x60) + w(spender) + w(sig_deadline) + details
    sig_off = 0x60 + len(struct) // 2
    return ("0x" + selector("permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)") + w(owner)
            + w(0x60) + w(sig_off) + struct + w(65) + "11" * 65 + "0" * 62)


def test_decode_permits_and_ms_fields():
    p = detectors.decode_permit(permit2612(V(1), a(0x5B), MS))
    assert (p["kind"], p["owner"], p["spender"], detectors.ms_deadline_fields(p)) == ("permit", V(1), a(0x5B), ["deadline"])
    p = detectors.decode_permit(permit_dai(V(1), a(0x5B), MS))
    assert p["kind"] == "permit_dai" and detectors.ms_deadline_fields(p) == ["expiry"]
    p = detectors.decode_permit(permit2_single(V(1), USDT, a(0x5B), MS, MS))
    assert (p["spender"], p["tokens"], detectors.ms_deadline_fields(p)) == (a(0x5B), [USDT], ["expiration", "sigDeadline"])
    p = detectors.decode_permit(permit2_batch(V(1), [USDT, WETH], a(0x5B), MS, 1_800_000_999))
    assert p["tokens"] == [USDT, WETH] and p["spender"] == a(0x5B)
    assert detectors.ms_deadline_fields(p) == ["expiration[0]", "expiration[1]"]
    assert detectors.ms_deadline_fields(detectors.decode_permit(permit2612(V(1), a(0x5B), 1_800_003_600))) == []
    assert detectors.decode_permit("0x" + selector("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")) is None


def test_k4_ms_deadline_tiers():
    op = a(0x0909)
    t = tx(tx_hash(60), op, USDT, permit2612(V(1), op, MS))
    _, rows = run_blocks({100: [t]})
    assert rows[op]["tier"] == "T2" and rows[op]["labels"] == ["ms_deadline"]
    pull = tx(tx_hash(61), op, USDT, "0x" + selector("transferFrom(address,address,uint256)") + w(V(1)) + w(a(0xC0)) + w(5 * 10 ** 6))
    logs = [transfer_log(tx_hash(61), USDT, V(1), a(0xC0), 5 * 10 ** 6, block=100)]
    _, rows = run_blocks({100: [t, pull]}, logs=logs)
    assert rows[op]["tier"] == "T1" and "ms_deadline_pull" in rows[op]["labels"]
    own = tx(tx_hash(62), V(1), USDT, permit2612(V(1), op, MS))                 # owner submits its own permit
    assert run_blocks({100: [own]})[1] == {}
    sec = tx(tx_hash(63), op, USDT, permit2612(V(1), op, TS0 + 3600))           # normal seconds deadline
    assert run_blocks({100: [sec]})[1] == {}


# ---------- K5 / K12 one-shot spenders ----------
def worker_txs(i, hub, fund=True, ret=True, nonce=0, ret_gas=ONESHOT_RETURN_GAS, base=100):
    wk, vic = a(0x1000 + i), V(100 + i)
    out = {base - 1: [], base: [], base + 1: []}
    if fund:
        out[base - 1].append(tx(tx_hash(1000 + 10 * i), hub, wk, "0x", 10 ** 15, gas=21_000))
    out[base].append(tx(tx_hash(1001 + 10 * i), wk, USDT,
                        "0x" + selector("transferFrom(address,address,uint256)") + w(vic) + w(hub) + w(500 * 10 ** 6),
                        nonce=nonce, gas=82_920))
    if ret:
        out[base + 1].append(tx(tx_hash(1002 + 10 * i), wk, hub, "0x", 10 ** 14, nonce=nonce + 1, gas=ret_gas))
    logs = [transfer_log(tx_hash(1001 + 10 * i), USDT, vic, hub, 500 * 10 ** 6, block=base, li=i)]
    return out, logs, wk


def k5_run(specs, hub=a(0x4B4B), codes=None):
    blocks, logs = {}, []
    for i, kw in enumerate(specs):
        b, lg, _ = worker_txs(i, hub, **kw)
        for n, ts in b.items():
            blocks.setdefault(n, []).extend(ts)
        logs += lg
    return run_blocks(blocks, logs=logs, codes=codes)


def test_k5_hub_tiers():
    hub = a(0x4B4B)
    ctx, rows = k5_run([{}])
    assert rows[hub]["tier"] == "T2" and "oneshot_hub" in rows[hub]["labels"]
    assert ctx.conn.execute("SELECT role FROM payouts WHERE drainer=? AND wallet=?", (hub, a(0x1000))).fetchone()[0] == "worker"
    _, rows = k5_run([{}, {"ret": False}, {"ret": False}])                 # 3 workers, one leftover return
    assert rows[hub]["tier"] == "T1" and {"oneshot_hub", "oneshot_multi"} <= set(rows[hub]["labels"])
    _, rows = k5_run([{"ret": False}])                                      # funded only (K12)
    assert rows[hub]["tier"] == "T3" and rows[hub]["labels"] == ["prefund_hub"]
    _, rows = k5_run([{"ret": False}] * 3)
    assert rows[hub]["tier"] == "T2" and "prefund_multi" in rows[hub]["labels"]


def test_k5_negatives_and_7702_hub():
    hub = a(0x4B4B)
    assert hub not in k5_run([{"fund": False, "ret_gas": 21_000}])[1]       # no fund, return with plain 21 000 gas
    assert hub not in k5_run([{"nonce": 10}])[1]                            # worker is not one-shot
    _, rows = k5_run([{}], codes={hub: CODE})                               # hub is a contract
    assert hub not in rows
    _, rows = k5_run([{}], codes={hub: "0xef0100" + "ab" * 20})             # K13 delegated hub: boost label
    assert {"oneshot_hub", "eip7702_operator"} <= set(rows[hub]["labels"])
    # the pull moved nothing (no Transfer log): ignored
    b, _, _ = worker_txs(0, hub)
    assert hub not in run_blocks(b)[1]


# ---------- K7 / K8 ----------
def test_k7_batch_approvals_drain():
    o, r, s1, s2, tk2 = V(1), a(0xEE0101), a(0x5A0101), a(0x5A0202), a(0x70C2C2)
    h = tx_hash(70)
    t = tx(h, o, o, "0x" + selector("execute((address,uint256,bytes)[])") + w(0))
    logs = [approval_log(h, USDT, o, s1, UINT256_MAX, li=0), approval_log(h, tk2, o, s2, KIT_AMOUNT, li=1),
            transfer_log(h, USDT, o, r, 900 * 10 ** 6, li=2)]
    _, rows = run_blocks({100: [t]}, logs=logs)
    assert rows[r]["tier"] == "T1" and "batch_approval_drain" in rows[r]["labels"]
    # victim receives the output itself: ordinary batch swap
    logs2 = logs + [transfer_log(h, WETH, a(0x9001), o, 10 ** 17, li=3)]
    assert r not in run_blocks({100: [t]}, logs=logs2, codes={a(0x9001): CODE})[1]
    # recipient is a contract / only one approval
    assert r not in run_blocks({100: [t]}, logs=logs, codes={r: CODE})[1]
    assert r not in run_blocks({100: [t]}, logs=[logs[0], logs[2]])[1]


def exact_input_single_r02(tin, tout, fee, rcpt, amount_in, out_min):
    return selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))") + w(tin) + w(tout) \
        + w(fee) + w(rcpt) + w(amount_in) + w(out_min) + w(0)


def test_k8_kit_amount_router_swap_and_v3_detail():
    o, r, pool = V(1), a(0xEE0202), a(0x900202)
    h = tx_hash(80)
    inner = exact_input_single_r02(USDT, WETH, 3000, r, 900 * 10 ** 6, 10 ** 17)
    batch = "0x" + selector("execute(bytes)") + w(0x20) + w(len(inner) // 2) + inner + "0" * ((-len(inner)) % 64)
    t = tx(h, o, o, batch)
    logs = [approval_log(h, USDT, o, ROUTER02, KIT_AMOUNT, li=0), transfer_log(h, USDT, o, pool, 900 * 10 ** 6, li=1),
            transfer_log(h, WETH, pool, r, 10 ** 17, li=2)]
    ctx, rows = run_blocks({100: [t]}, logs=logs, codes={pool: CODE})
    assert rows[r]["tier"] == "T1" and rows[r]["labels"] == ["kit_router_swap"]
    import json
    d = json.loads(ctx.conn.execute("SELECT detail FROM evidence WHERE type='kit_router_swap'").fetchone()[0])
    assert d["v3"][0]["fee"] == 3000 and d["v3"][0]["recipient"] == r and d["approvals"][0]["spender"] == ROUTER02
    assert pool not in rows                                                  # the pool is a contract: never a subject
    # plain MAX approval to the router (not the kit amount): no K8
    logs[0] = approval_log(h, USDT, o, ROUTER02, UINT256_MAX, li=0)
    assert r not in run_blocks({100: [t]}, logs=logs, codes={pool: CODE})[1]


def test_d10_v3_exact_input_single_kit_shape():
    r = a(0xEE0303)
    v1 = lambda fee, dl, mn: ("0x" + selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))")  # noqa: E731
                              + w(USDT) + w(WETH) + w(fee) + w(r) + w(dl) + w(10 ** 6) + w(mn) + w(0))
    (s,) = detectors.decode_swaps(v1(3000, TS0 + 400, 5))
    assert (s["fee"], s["to"], s["deadline"], s["amount_in"], s["amount_out_min"]) == (3000, r, TS0 + 400, 10 ** 6, 5)
    c = detectors.d10_candidate(s, V(1), TS0 + 100)
    assert c["v3_kit_shape"] and not c["kit"]
    assert detectors.d10_candidate(detectors.decode_swaps(v1(500, TS0 + 400, 5))[0], V(1), TS0 + 100) is None
    assert detectors.d10_candidate(detectors.decode_swaps(v1(3000, TS0 + 1900, 5))[0], V(1), TS0 + 100) is None
    t = tx(tx_hash(90), V(1), "0xe592427a0aece92de3edee1f18e0157c05861564", v1(3000, TS0 + 100 + 300, 5))
    _, rows = run_blocks({100: [t]})
    assert rows[r]["tier"] == "T3" and rows[r]["labels"] == ["foreign_recipient_swap"]


# ---------- K9 OwnerCollector ----------
def test_real_owner_collector_runtime_is_classified():
    info = bytecode.analyze(oc_code())
    assert info["kit"] == "owner_collector" and info["size"] == 2591
    assert set(info["selectors"]) == {"d253abea", "130cbae0", "889d79b0", "e5711e8b", "13af4035", "8da5cb5b"}
    assert bytecode.kit_family(["13af4035", "8da5cb5b", "e5711e8b", "889d79b0", "6eb1769f"]) is None   # no collect fn


def _oc_chunk(victims, to=OC, codes=None):
    logs, rcs = [], []
    for i, v in enumerate(victims):
        h = tx_hash(2000 + i)
        lg = [transfer_log(h, USDT, v, OC_OWNER, 7999 * 10 ** 6, block=100, li=i)]
        logs += lg
        rcs.append({"transactionHash": h, "from": OC_OWNER, "to": to, "blockNumber": hex(100), "contractAddress": None,
                    "status": "0x1", "logs": lg})
    ctx = make_ctx(FakeRpc(codes=codes if codes is not None else {OC: oc_code()}, symbols={USDT: ("USDT", 6)},
                           nonces={v: 2 for v in victims}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=split_receipts(rcs)[1])
    return ctx, {r["address"]: r for r in rollup.rollup(ctx.conn, SeedSet(), {})}


def test_k9_owner_collect_behaviour():
    ctx, rows = _oc_chunk([OC_VICTIM])
    r = rows[OC]
    assert r["tier"] == "T2" and {"owner_collect", "kit_signature"} <= set(r["labels"]) and r["family"] == "owner_collector"
    assert ctx.conn.execute("SELECT wallet, role FROM payouts WHERE drainer=?", (OC,)).fetchall()[0][:] == (OC_OWNER, "collector")
    assert ctx.conn.execute("SELECT victim, recipient, usd FROM drains").fetchone()[:] == (OC_VICTIM, OC_OWNER, 7999.0)
    _, rows = _oc_chunk([OC_VICTIM, V(1), V(2)])
    assert rows[OC]["tier"] == "T1" and rows[OC]["victims"] == 3
    _, rows = _oc_chunk([OC_VICTIM], codes={OC: CODE})                       # not the kit / not a puller
    assert OC not in rows
    _, rows = _oc_chunk([OC_VICTIM], codes={OC: oc_code(), OC_OWNER: "0xef0100" + "cd" * 20})
    assert "eip7702_operator" in rows[OC]["labels"]                           # K13 boost


# ---------- K14 cross-chain ----------
def test_k14_cross_chain_rows_and_payload():
    ctx = make_ctx()
    c, x = ctx.conn, a(0xC4C4)
    for ch in ("eth", "bsc"):
        c.execute("INSERT INTO codes VALUES(?,?,?,?,?,?)", (ch, x, "0x1", 200, "sk", "[]"))
    add_evidence(c, "eth", x, "approval_fingerprint", tx_hash(1), 1, TS0, dict(victim=V(1), token=USDT, kit="ms_drainer"))
    add_evidence(c, "bsc", x, "bytecode", tx_hash(2), 1, TS0, dict(redflags=["Claim()"]))
    c.commit()
    rows = {(r["chain"], r["address"]): r for r in rollup.rollup(c, SeedSet(), {})}
    assert rows[("eth", x)]["tier"] == "T1" and "cross_chain" in rows[("eth", x)]["labels"]
    assert rows[("bsc", x)]["tier"] == "T2" and {"cross_chain", "cross_chain_t1"} <= set(rows[("bsc", x)]["labels"])
    p = {(q["chain"], q["address"]): q for q in build_payload(c)["contracts"]}
    assert p[("eth", x)]["cross_chain"] == [dict(chain="bsc", tier="T2")]


def test_k14_enrich_cross_chain_check():
    ctx = make_ctx()
    c, x = ctx.conn, a(0xC5C5)
    info = bytecode.analyze(CODE)
    c.execute("INSERT INTO codes VALUES('eth',?,?,?,?,?)", (x, info["code_hash"], info["size"], info["skeleton"], "[]"))
    add_evidence(c, "eth", x, "approval_fingerprint", tx_hash(1), 1, TS0, dict(victim=V(1), token=USDT, kit="ms_drainer"))
    c.commit()
    rollup.rollup(c, SeedSet(), {})
    n = enrich.cross_chain_check(c, {"bsc": FakeRpc(codes={x: CODE}), "base": FakeRpc()})
    assert n == 1
    rows = {(r["chain"], r["address"]): r for r in rollup.rollup(c, SeedSet(), {})}
    assert rows[("bsc", x)]["tier"] == "T2" and "cross_chain_t1" in rows[("bsc", x)]["labels"]
    assert ("base", x) not in rows
    assert enrich.cross_chain_check(c, {"bsc": FakeRpc(codes={x: CODE}), "base": FakeRpc()}) == 0   # cached


def test_describe_new_evidence_types():
    for t, d in (("ms_deadline", dict(kind="permit", submitter=a(1), victim=a(2), values={"deadline": "1"}, pulled=True)),
                 ("oneshot_spender", dict(worker=a(1), worker_nonce=0, token=USDT, victim=a(2), recipient=a(3),
                                          fund_tx="0x1", return_tx="0x2")),
                 ("kit_deposit", dict(depositer=a(1), nonce=1, gas_limit=100000, value_wei="1", balance_share=0.99)),
                 ("batch_approval_drain", dict(victim=a(1), legs=[{}])), ("kit_router_swap", dict(victim=a(1), legs=[])),
                 ("owner_collect", dict(token=USDT, victim=a(1), collector=a(2), kit="owner_collector")),
                 ("cross_chain", dict(linked_chain="bsc", linked_tier="T1")),
                 ("gen_back_transfer", dict(deployer=a(1), wallet=a(2), value_wei="5"))):
        s = describe(t, d)
        assert s and not s.startswith("{"), t
