"""Synthetic logs / fake RPC for tests."""
from drainerwatch.constants import TOPIC_APPROVAL, TOPIC_TRANSFER
from drainerwatch.db import connect
from drainerwatch.prices import Prices
from drainerwatch.scan import Ctx
from drainerwatch.seeds import SeedSet


def a(n: int) -> str:
    return "0x" + f"{n:040x}"


def pad(addr: str) -> str:
    return "0x" + "0" * 24 + addr[2:]


def tx_hash(n: int) -> str:
    return "0x" + f"{n:064x}"


def transfer_log(tx, token, frm, to, value, block=100, li=0):
    return dict(transactionHash=tx, logIndex=hex(li), blockNumber=hex(block), address=token,
                topics=[TOPIC_TRANSFER, pad(frm), pad(to)], data="0x" + f"{value:064x}")


def approval_log(tx, token, owner, spender, value=1, block=100, li=0):
    return dict(transactionHash=tx, logIndex=hex(li), blockNumber=hex(block), address=token,
                topics=[TOPIC_APPROVAL, pad(owner), pad(spender)], data="0x" + f"{value:064x}")


def sym_hex(s):
    return "0x" + s.encode().ljust(32, b"\0").hex()


class FakeRpc:
    """Implements the subset of Rpc used by Ctx/Tokens."""
    chain = "eth"

    def __init__(self, txs=None, codes=None, symbols=None, nonces=None):
        self.txs, self.codes, self.symbols = txs or {}, codes or {}, symbols or {}
        self.nonce_map = nonces or {}
        self.calls = self.limit_hits = self.errors = 0

    def block_times(self, numbers):
        return {n: 1_800_000_000 + n for n in numbers}

    def txs_by_hash(self, hashes):
        return {h: self.txs[h] for h in hashes if h in self.txs}

    def nonces(self, addrs):
        return {x: self.nonce_map.get(x, 10) for x in addrs}

    def get_code_many(self, addrs):
        return {x: self.codes.get(x, "0x") for x in addrs}

    def eth_call_many(self, calls):
        out = []
        for to, data in calls:
            sym, dec = self.symbols.get(to, ("TKN", 18))
            out.append(sym_hex(sym) if data.startswith("0x95d89b41") else "0x" + f"{dec:064x}")
        return out


def make_ctx(rpc=None, seeds=None, labels=None, chain="eth", native=None):
    conn = connect(":memory:")
    return Ctx(conn, chain, rpc or FakeRpc(), seeds or SeedSet(), labels or {}, Prices(None, native or {"ETH": 2000.0}))


def tx_info(frm, to, block=100):
    return {"from": frm, "to": to, "blockNumber": hex(block), "input": "0x", "value": "0x0", "hash": "0x"}
