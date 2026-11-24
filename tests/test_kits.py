"""Kit signatures from kit notes (MS Drainer S1-S4, VerifyAccount case A): bytecode fingerprints, D7 bait(address),
D9 approval fingerprint, D10 foreign-recipient swaps, R-A1 cross-tx split, R-A2 owner-gated puller, R-A4 clusters."""
import json
from pathlib import Path

from drainerwatch import bytecode, detectors, rollup, scan
from drainerwatch.constants import CHAINS, KIT_APPROVAL_AMOUNTS
from drainerwatch.db import add_evidence
from drainerwatch.render import build_payload
from drainerwatch.rpc import parse_logs, split_receipts
from drainerwatch.seeds import SeedSet
from drainerwatch.util import selector
from tests.helpers import FakeRpc, a, approval_log, make_ctx, transfer_log, tx_hash

KITS = Path(__file__).parent / "fixtures_kits"
MS_ETH = "0xacbd7c3357687be445985fcab1ff4551c88aa375"
MS_BSC = "0xd4d7e9e1d0dae333d83e174572de6bc473378bf1"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
WETH = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"
CODE = "0x" + "60806040" * 40
V = lambda i: a(0xABC000 + i)  # noqa: E731


def kit_code(chain, addr):
    return (KITS / f"ms_drainer_{chain}_{addr}.hex").read_text().strip()


def w(x) -> str:
    return f"{int(x, 16) if isinstance(x, str) else x:064x}"


# ---------- S1 / R-A3 bytecode ----------
def test_real_ms_drainer_runtime_is_classified():
    for chain, addr in (("eth", MS_ETH), ("bsc", MS_BSC)):
        info = bytecode.analyze(kit_code(chain, addr))
        assert info["kit"] == "ms_drainer", chain
        assert "Claim(address)" in info["redflags"] and "SecurityUpdate(address)" in info["redflags"]
        assert not info["owner_gated_puller"]


def test_kit_family_thresholds():
    bait, comp = selector("Claim(address)"), [selector("getOwner()"), selector("getBalance()")]
    assert bytecode.kit_family([bait] + comp) == "ms_drainer"
    assert bytecode.kit_family([bait, comp[0]]) is None              # one companion is not enough
    assert bytecode.kit_family(comp + [selector("withdraw(address)")]) is None   # no bait function
    assert bytecode.kit_family(["5082dd12", "ea4418d9"]) == "verify_account"
    assert bytecode.kit_family(["5082dd12"]) is None


# ---------- R-A2 owner-gated parametric puller ----------
def _puller(owner_check=True, addr20="ff" * 20, dispatch_tf=False):
    disp = "600035" "60e01c" "80" "63" + ("23b872dd" if dispatch_tf else "5082dd12") + "14" "610000" "57"
    own = "600054" "73" + addr20 + "16" "33" "14" "610000" "57" if owner_check else ""
    body = "63" "23b872dd" "60e01b" "600052" "600435" "5a" "f1" "00"
    return "0x" + disp + own + body


def test_owner_gated_puller_heuristic():
    assert bytecode.owner_gated_puller(_puller())
    assert not bytecode.owner_gated_puller(_puller(owner_check=False))             # anyone can call
    assert not bytecode.owner_gated_puller(_puller(addr20="11" * 20))              # hard-coded address
    assert not bytecode.owner_gated_puller(_puller(dispatch_tf=True))              # the contract is a token
    assert not bytecode.owner_gated_puller(CODE)
    # tier: T3 static alone, T2 with behavioural evidence
    assert detectors.assign_tier({"owner_gated_puller"}, 0, False) == "T3"
    assert detectors.assign_tier({"owner_gated_puller", "multi_victim_pull"}, 3, True) == "T2"


# ---------- D7 bait(address) ----------
class BlockRpc(FakeRpc):
    def __init__(self, blocks=(), **kw):
        super().__init__(**kw)
        self.blocks = {b["number"]: b for b in blocks}

    def blocks_full(self, nums, chunk=5):
        return [self.blocks.get(hex(n)) for n in nums]

    def receipts(self, hashes):
        return {h: {"status": "0x1", "contractAddress": None} for h in hashes}


def block(n, txs, ts=None):
    return {"number": hex(n), "timestamp": hex(ts or 1_800_000_000 + n), "transactions": txs}


def call_tx(h, frm, to, inp, value=0):
    return {"hash": h, "type": "0x2", "from": frm, "to": to, "value": hex(value), "input": inp}


def meta_of(txs, block_n=100):
    return {t["hash"]: {"from": t["from"], "to": t["to"], "block": block_n, "created": None, "status": 1} for t in txs}


def bait_input(name, customer):
    return "0x" + selector(name) + w(customer)


def test_decode_bait():
    sel, name, cust = detectors.decode_bait(bait_input("SecurityUpdate(address)", a(0xC1C1C1)))
    assert (name, cust) == ("SecurityUpdate(address)", a(0xC1C1C1))
    assert detectors.decode_bait("0x" + selector("Claim()")) is None
    assert detectors.decode_bait("0x" + selector("Claim(address)") + "f" * 64) is None   # not an address word


def _bait_run(victims, customer=a(0xC1C1C1)):
    txs = [call_tx(tx_hash(500 + i), v, MS_ETH, bait_input("Claim(address)", customer), 10 ** 17)
           for i, v in enumerate(victims)]
    rpc = BlockRpc([block(100, txs)], codes={MS_ETH: kit_code("eth", MS_ETH)})
    ctx = make_ctx(rpc)
    scan.eth_block_pass(ctx, 100, 100, txmeta=meta_of(txs))
    return ctx


def test_d7_bait_customer_and_tiers():
    ctx = _bait_run([V(1)])
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["address"] == MS_ETH and r["tier"] == "T2" and r["family"] == "ms_drainer"
    assert {"bait_payable", "kit_signature", "redflag_selectors"} <= set(r["labels"])
    assert ctx.conn.execute("SELECT wallet, role FROM payouts").fetchall()[0][:] == (a(0xC1C1C1), "customer")
    d = ctx.conn.execute("SELECT victim, drainer, recipient, symbol, amount FROM drains").fetchone()
    assert d[:] == (V(1), MS_ETH, a(0xC1C1C1), "ETH", "0.1")
    ctx = _bait_run([V(1), V(2), V(3)])
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T1" and r["victims"] == 3
    # self-crediting call (argument == sender) is no customer attribution: plain red-flag payable (T3)
    ctx = _bait_run([V(1)], customer=V(1))
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert "bait_payable" not in r["labels"] and "redflag_payable" in r["labels"]


def test_d7_withdraw_callers_are_customers():
    ctx = _bait_run([V(1)])
    rollup.rollup(ctx.conn, SeedSet(), {})
    ctx.bait_set = None
    wtx = [call_tx(tx_hash(900), a(0xC2C2C2), MS_ETH, "0x" + selector("withdraw(address)") + w(a(0xC2C2C2)))]
    ctx.rpc.blocks = {hex(101): block(101, wtx)}
    scan.eth_block_pass(ctx, 101, 101, txmeta=meta_of(wtx, 101))
    roles = dict(ctx.conn.execute("SELECT wallet, role FROM payouts").fetchall())
    assert roles == {a(0xC1C1C1): "customer", a(0xC2C2C2): "customer"}
    # withdraw(address) on a contract that is not a known bait contract: ignored
    ctx2 = make_ctx(BlockRpc([block(101, [call_tx(tx_hash(901), a(0xC2C2C2), a(0x51), wtx[0]["input"])])]))
    scan.eth_block_pass(ctx2, 101, 101, txmeta=meta_of([call_tx(tx_hash(901), a(0xC2C2C2), a(0x51), "0x")], 101))
    assert ctx2.conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0] == 0


# ---------- D9 approval fingerprint ----------
def test_d9_approval_fingerprint():
    kit_amount = next(iter(KIT_APPROVAL_AMOUNTS))
    spender = a(0x5E)
    logs = [approval_log(tx_hash(1), USDT, V(1), spender, kit_amount),
            approval_log(tx_hash(2), USDT, V(2), a(0x5F), 2 ** 256 - 1)]       # plain unlimited: no fingerprint
    ctx = make_ctx(FakeRpc(symbols={USDT: ("USDT", 6)}))
    scan.process_chunk(ctx, 100, 100, logs)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert (r["address"], r["tier"], r["victims"]) == (spender, "T1", 1) and "approval_fingerprint" in r["labels"]
    tr, ap = parse_logs([approval_log(tx_hash(3), USDT, V(1), a(0x5E), kit_amount)])
    assert detectors.d9_candidates(ap, lambda x: x == a(0x5E)) == []             # allowlisted spender


# ---------- D10 foreign-recipient swap ----------
def v2_swap(amount_in, out_min, path, to, deadline, name="swapExactTokensForETH(uint256,uint256,address[],address,uint256)"):
    return ("0x" + selector(name) + w(amount_in) + w(out_min) + w(0xA0) + w(to) + w(deadline) + w(len(path))
            + "".join(w(p) for p in path))


def multicall_swap(deadline, amount_in, out_min, path, to):
    inner = (selector("swapExactTokensForTokens(uint256,uint256,address[],address)") + w(amount_in) + w(out_min)
             + w(0x80) + w(to) + w(len(path)) + "".join(w(p) for p in path))
    ln = len(inner) // 2
    inner_padded = inner + "0" * ((-len(inner)) % 64)
    return ("0x" + selector("multicall(uint256,bytes[])") + w(deadline) + w(0x40) + w(1) + w(0x20) + w(ln)
            + inner_padded)


def test_decode_swaps_v2_and_multicall():
    (s,) = detectors.decode_swaps(v2_swap(5, 0, [USDT, WETH], a(0xEEEEEE), 123))
    assert (s["amount_in"], s["amount_out_min"], s["path"], s["to"], s["deadline"]) == (5, 0, [USDT, WETH], a(0xEEEEEE), 123)
    (m,) = detectors.decode_swaps(multicall_swap(777, 9, 0, [USDT, WETH], a(0xEEEEEE)))
    assert (m["amount_in"], m["to"], m["deadline"], m["path"]) == (9, a(0xEEEEEE), 777, [USDT, WETH])
    assert detectors.decode_swaps("0x1234") == [] and detectors.decode_swaps("0x" + selector("multicall(uint256,bytes[])")) == []


def _swap_run(victims, recipient=a(0xEEEEEE), delta=99990, out_min=0, codes=None, multicall=False):
    n = 100
    ts = 1_800_000_000 + n
    txs = []
    for i, v in enumerate(victims):
        to = recipient if recipient is not None else v
        inp = (multicall_swap(ts + delta, 10 ** 6, out_min, [USDT, WETH], to) if multicall
               else v2_swap(10 ** 6, out_min, [USDT, WETH], to, ts + delta))
        txs.append(call_tx(tx_hash(700 + i), v, "0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f", inp))
    ctx = make_ctx(BlockRpc([block(n, txs)], codes=codes or {}, symbols={USDT: ("USDT", 6)}))
    scan.eth_block_pass(ctx, n, n, txmeta=meta_of(txs))
    return rollup.rollup(ctx.conn, SeedSet(), {}), ctx


def test_d10_tiers_and_guards():
    rows, ctx = _swap_run([V(1), V(2), V(3)])
    (r,) = rows
    assert (r["address"], r["tier"]) == (a(0xEEEEEE), "T1") and {"foreign_swap_multi", "foreign_swap_kit"} <= set(r["labels"])
    assert ctx.conn.execute("SELECT COUNT(*), SUM(usd) FROM drains").fetchone()[:] == (3, 3.0)
    (r,), _ = _swap_run([V(1), V(2), V(3)], delta=1200)                          # ordinary 20-min deadline
    assert r["tier"] == "T2" and "foreign_swap_kit" not in r["labels"]
    (r,), _ = _swap_run([V(1)], delta=1200)
    assert r["tier"] == "T3" and r["labels"] == ["foreign_recipient_swap"]
    (r,), _ = _swap_run([V(1)], multicall=True)                                 # SwapRouter02 multicall, kit deadline
    assert r["tier"] == "T2" and "foreign_swap_kit" in r["labels"]
    assert _swap_run([V(1), V(2), V(3)], out_min=1)[0] == []                     # slippage protected
    assert _swap_run([V(1), V(2), V(3)], recipient=None)[0] == []                # pays the signer itself
    assert _swap_run([V(1), V(2), V(3)], codes={a(0xEEEEEE): CODE})[0] == []         # recipient is a contract


# ---------- R-A1 cross-tx split ----------
def _rc(h, frm, to, logs, blk):
    return {"transactionHash": h, "from": frm, "to": to, "blockNumber": hex(blk), "contractAddress": None,
            "status": "0x1", "logs": logs}


def xsplit_chunk(victim, values, recipients, caller=a(0x0B), to=a(0x9C), blocks=None, token=USDT, base=0):
    logs, rcs = [], []
    for i, (val, rcp) in enumerate(zip(values, recipients)):
        blk = (blocks or [100] * len(values))[i]
        h = tx_hash(3000 + base + i)
        lg = [transfer_log(h, token, victim, rcp, val, block=blk, li=i)]
        logs += lg
        rcs.append(_rc(h, caller, to or token, lg, blk))
    return logs, split_receipts(rcs)[1]


def test_xsplit_98_2_in_two_txs_contract_puller():
    puller = a(0x9C)
    logs, meta = xsplit_chunk(V(1), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)])
    ctx = make_ctx(FakeRpc(codes={puller: CODE}, symbols={USDT: ("USDT", 6)}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert (r["address"], r["tier"], r["labels"]) == (puller, "T3", ["split_xtx"])
    pay = dict((w_, (role, s)) for w_, role, s in ctx.conn.execute("SELECT wallet, role, share FROM payouts"))
    assert pay == {a(0xD1): ("affiliate", 0.98), a(0xD2): ("operator", 0.02)}
    # three victims (one chunk each) -> T1
    for i in (2, 3):
        logs, meta = xsplit_chunk(V(i), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)], base=10 * i)
        scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T1" and r["victims"] == 3


def test_xsplit_negatives_and_carry():
    puller = a(0x9C)
    mk = lambda: make_ctx(FakeRpc(codes={puller: CODE}, symbols={USDT: ("USDT", 6)}))  # noqa: E731
    for kw in (dict(values=[50, 50]),                                   # 50/50 is no fee split
               dict(values=[98, 2], blocks=[100, 200]),                 # 100 s apart
               dict(values=[98, 2], recipients=[a(0xD1), a(0xD1)])):    # one recipient
        args = dict(values=[98_000_000, 2_000_000], recipients=[a(0xD1), a(0xD2)])
        args.update({k: ([x * 10 ** 6 for x in v] if k == "values" else v) for k, v in kw.items()})
        logs, meta = xsplit_chunk(V(1), **args)
        ctx = mk()
        scan.process_chunk(ctx, 100, 200, logs, txmeta=meta)
        assert rollup.rollup(ctx.conn, SeedSet(), {}) == [], kw
    # split straddling a chunk boundary (blocks 100 | 101): carried over
    logs, meta = xsplit_chunk(V(1), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)], blocks=[100, 101])
    ctx = mk()
    scan.process_chunk(ctx, 100, 100, [lg for lg in logs if lg["blockNumber"] == hex(100)], txmeta=meta)
    scan.process_chunk(ctx, 101, 101, [lg for lg in logs if lg["blockNumber"] == hex(101)], txmeta=meta)
    assert [r["labels"] for r in rollup.rollup(ctx.conn, SeedSet(), {})] == [["split_xtx"]]
    # victim with nonce < 3 (custodial deposit address): no flag
    logs, meta = xsplit_chunk(V(1), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)])
    ctx = make_ctx(FakeRpc(codes={puller: CODE}, symbols={USDT: ("USDT", 6)}, nonces={V(1): 1}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []


def test_xsplit_eoa_spender_via_token():
    logs, meta = xsplit_chunk(V(1), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)], to=None)
    ctx = make_ctx(FakeRpc(symbols={USDT: ("USDT", 6)}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["address"] == a(0x0B) and {"split_xtx", "eoa_spender_pull"} <= set(r["labels"])


# ---------- R-A4 clusters ----------
def _cluster_db(link_txs=2, b_ev="eoa_spender_pull", w2=None):
    ctx = make_ctx()
    c = ctx.conn
    A, B, W = a(0xA1), a(0xB1), a(0x77)
    add_evidence(c, "eth", A, "split_pull", tx_hash(1), 1, 1_800_000_000,
                 dict(victims=[V(1), V(2), V(3)], token=USDT, recipients=[]))
    c.execute("INSERT INTO payouts VALUES('eth',?,?,'operator',0.1,1)", (A, W))
    if b_ev == "eoa_spender_pull":
        add_evidence(c, "eth", B, b_ev, tx_hash(2), 1, 1_800_000_000, dict(victim=V(9), recipient=W, token=USDT))
    else:
        add_evidence(c, "eth", B, "bytecode", tx_hash(2), 1, 1_800_000_000, dict(redflags=["Claim()"]))
    c.execute("INSERT INTO payouts VALUES('eth',?,?,'collector',NULL,?)", (B, W, link_txs))
    if w2:
        c.execute("INSERT INTO payouts VALUES('eth',?,?,'operator',0.1,1)", (A, w2))
        c.execute("INSERT INTO payouts VALUES('eth',?,?,'collector',NULL,1)", (B, w2))
    c.commit()
    return c, {r["address"]: r for r in rollup.rollup(c, SeedSet(), {})}


def test_cluster_shared_collector_and_inheritance():
    c, rows = _cluster_db(link_txs=2)
    A, B = rows[a(0xA1)], rows[a(0xB1)]
    assert A["cluster"] and A["cluster"] == B["cluster"]
    assert A["tier"] == "T1" and B["tier"] == "T2" and "cluster_inherited" in B["labels"]
    p = build_payload(c)
    (cl,) = p["clusters"]
    assert cl["members"] == sorted([a(0xA1), a(0xB1)]) and cl["shared_wallets"] == [a(0x77)] and cl["max_tier"] == "T1"
    assert {x["address"]: x["cluster"] for x in p["contracts"] if "operator_wallet" not in x["labels"]} ==         {a(0xA1): cl["cluster"], a(0xB1): cl["cluster"]}
    assert [x["labels"] for x in p["contracts"] if x["address"] == a(0x77)] == [["operator_wallet"]]   # W12 hub, T3


def test_cluster_no_inheritance_from_single_weak_link_or_static_member():
    _, rows = _cluster_db(link_txs=1)                                  # one shared wallet, one tx: weak
    assert rows[a(0xB1)]["tier"] == "T3" and rows[a(0xB1)]["cluster"] == rows[a(0xA1)]["cluster"]
    _, rows = _cluster_db(link_txs=1, w2=a(0x78))                      # two shared wallets: enough
    assert rows[a(0xB1)]["tier"] == "T2"
    _, rows = _cluster_db(link_txs=5, b_ev="bytecode")                 # static-only member: no independent evidence
    assert rows[a(0xB1)]["tier"] == "T3" and "cluster_inherited" not in rows[a(0xB1)]["labels"]


# ---------- source default ----------
def test_default_source_per_chain(monkeypatch):
    monkeypatch.delenv("DRAINERWATCH_SOURCE", raising=False)
    assert CHAINS["eth"]["source"] == "receipts" and CHAINS["base"]["source"] == "receipts"

    class R(FakeRpc):
        def __init__(self):
            super().__init__()
            self.used = None
            self.last_size = None

        def block_number(self):
            return 1000

        def iter_receipts(self, a_, b_, deadline, size=10):
            self.used = "receipts"
            return iter(())

        def iter_logs(self, a_, b_, deadline, size):
            self.used = "logs"
            return iter(())

    for chain, expect in (("eth", "receipts"), ("bsc", "logs"), ("base", "receipts")):
        rpc = R()
        ctx = make_ctx()
        st = scan.scan_chain(ctx.conn, chain, SeedSet(), {}, ctx.prices, rpc=rpc, start=10, end=12, persist_cursor=False)
        assert rpc.used == expect and st["source"] == expect
    monkeypatch.setenv("DRAINERWATCH_SOURCE", "logs")
    rpc = R()
    scan.scan_chain(make_ctx().conn, "eth", SeedSet(), {}, ctx.prices, rpc=rpc, start=10, end=12, persist_cursor=False)
    assert rpc.used == "logs"



def test_guards_relayer_caller_and_unpriced_swap_farm():
    # batch-transfer relayer: caller nonce >= 2000 -> no cross-tx split
    puller = a(0x9C)
    logs, meta = xsplit_chunk(V(1), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)])
    ctx = make_ctx(FakeRpc(codes={puller: CODE}, symbols={USDT: ("USDT", 6)}, nonces={a(0x0B): 11_808}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    assert rollup.rollup(ctx.conn, SeedSet(), {}) == []
    # 3 wallets dumping an unpriced (meme) token to one EOA with a short deadline: stays T3
    meme = a(0x3E3E3E)
    n, ts = 100, 1_800_000_100
    txs = [call_tx(tx_hash(800 + i), V(i), "0x7a250d5630b4cf539739df2c5dacb4c659f2488d",
                   v2_swap(10 ** 18, 0, [meme, WETH], a(0xEEEEEE), ts + 51)) for i in range(3)]
    ctx = make_ctx(BlockRpc([block(n, txs)], symbols={meme: ("MEME", 18)}))
    scan.eth_block_pass(ctx, n, n, txmeta=meta_of(txs))
    (r,) = rollup.rollup(ctx.conn, SeedSet(), {})
    assert r["tier"] == "T3" and r["labels"] == ["foreign_recipient_swap"]


def test_xsplit_high_nonce_eoa_spender_kept_batch_tx_dropped():
    # EOA spender calling the token: no nonce cap (real operators split across txs with 2.1k / 13.9k nonces)
    logs, meta = xsplit_chunk(V(1), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)], to=None)
    ctx = make_ctx(FakeRpc(symbols={USDT: ("USDT", 6)}, nonces={a(0x0B): 13_855}))
    scan.process_chunk(ctx, 100, 100, logs, txmeta=meta)
    assert any("split_xtx" in r["labels"] for r in rollup.rollup(ctx.conn, SeedSet(), {}))
    # the same split inside batch txs that also move tokens of 2 other owners: relayer, no split evidence
    puller = a(0x9C)
    logs, meta = xsplit_chunk(V(1), [98_000_000, 2_000_000], [a(0xD1), a(0xD2)])
    extra = []
    for i, lg in enumerate(list(logs)):
        for j in (1, 2):
            extra.append(transfer_log(lg["transactionHash"], USDT, V(50 + 10 * i + j), a(0xE0 + j), 1_000_000,
                                      li=10 + 10 * i + j))
    ctx = make_ctx(FakeRpc(codes={puller: CODE}, symbols={USDT: ("USDT", 6)}))
    scan.process_chunk(ctx, 100, 100, logs + extra, txmeta=meta)
    assert all("split_xtx" not in r["labels"] for r in rollup.rollup(ctx.conn, SeedSet(), {}))
