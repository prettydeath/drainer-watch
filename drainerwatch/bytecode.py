"""EVM bytecode analysis: skeleton hash, 4-byte selector set, red-flag selectors, family matching, sweeper heuristic."""
import hashlib

from .constants import (BAIT_ADDR_SELECTORS, ERC20_MIN_SELECTORS, ERC20_SELECTORS, BUYTRON_FAMILIES, FAMILY_JACCARD, FAMILY_MIN_CODE, FAMILY_MIN_SELECTORS, GEN_BAIT_RUNTIME_KECCAK,
                        GEN_BAIT_SELECTORS, GEN_BAIT_SIZE, KIT_PUBLIC_RUNTIME_KECCAK, MS_COMPANION_SELECTORS, MS_MIN_BAIT, MS_MIN_COMPANION,
                        MS_NEW_COMPANION_SELECTORS, MS_NEW_MIN_BAIT, MS_NEW_MIN_COMPANION, MS_NEW_SELECTORS,
                        OWNER_COLLECTOR_MIN, OWNER_COLLECTOR_SELECTORS, REDFLAG_SELECTORS, SEL_TRANSFER_FROM,
                        SWEEPER_MAX_CODE, TRUSTY_V1_MIN_BAIT, TRUSTY_V1_SELECTORS, VERIFY_ACCOUNT_MIN,
                        VERIFY_ACCOUNT_SELECTORS, TRON_SWEEPER_SELECTORS, FORWARDER_7702_SELECTORS)
from .util import keccak

OP_PUSH1, OP_PUSH4, OP_PUSH20, OP_PUSH32 = 0x60, 0x63, 0x73, 0x7F
OP_EQ, OP_CALLVALUE, OP_SLOAD, OP_CALL, OP_JUMPI = 0x14, 0x34, 0x54, 0xF1, 0x57
OP_CALLER, OP_CALLDATALOAD = 0x33, 0x35
OP_DELEGATECALL = 0xF4
OP_PUSH2, OP_SSTORE = 0x61, 0x55
_META_MARKERS = (b"ipfs", b"bzzr", b"solc", b"experimental")
# TVM (TRON) extensions, all single-byte (no immediates, so iter_ops needs no change): TRC-10 token calls / msg.tokenvalue /
# msg.tokenid, isContract, staking and resource delegation. CALLTOKEN is a CALL that also moves a TRC-10 token.
TVM_OPS = {0xD0: "CALLTOKEN", 0xD1: "TOKENBALANCE", 0xD2: "CALLTOKENVALUE", 0xD3: "CALLTOKENID", 0xD4: "ISCONTRACT",
           0xD5: "FREEZE", 0xD6: "UNFREEZE", 0xD7: "FREEZEEXPIRETIME", 0xD8: "VOTEWITNESS", 0xD9: "WITHDRAWREWARD",
           0xDA: "FREEZEBALANCEV2", 0xDB: "UNFREEZEBALANCEV2", 0xDC: "CANCELALLUNFREEZEV2", 0xDD: "WITHDRAWEXPIREUNFREEZE",
           0xDE: "DELEGATERESOURCE", 0xDF: "UNDELEGATERESOURCE"}
OP_CALLTOKEN = 0xD0


def to_bytes(code) -> bytes:
    if isinstance(code, (bytes, bytearray)):
        return bytes(code)
    c = (code or "0x")
    c = c[2:] if c.startswith("0x") else c
    return bytes.fromhex(c)


def strip_metadata(code: bytes) -> bytes:
    """Remove the trailing Solidity CBOR metadata blob (last 2 bytes = its length)."""
    if len(code) < 4:
        return code
    n = int.from_bytes(code[-2:], "big")
    if 4 <= n and n + 2 <= len(code):
        meta = code[-(n + 2):-2]
        if 0xA1 <= meta[0] <= 0xA6 and any(m in meta for m in _META_MARKERS):
            return code[:-(n + 2)]
    return code


def iter_ops(code: bytes):
    """Yield (offset, opcode, immediate_bytes)."""
    i, n = 0, len(code)
    while i < n:
        op = code[i]
        if OP_PUSH1 <= op <= OP_PUSH32:
            k = op - OP_PUSH1 + 1
            yield i, op, code[i + 1:i + 1 + k]
            i += 1 + k
        else:
            yield i, op, b""
            i += 1


def skeleton_hash(code: bytes) -> str:
    """sha256 over the opcode stream: PUSH immediates zeroed (only the opcode, i.e. the push width, is kept),
    trailing CBOR metadata stripped. Two builds of the same source with different constants/metadata collide."""
    body = strip_metadata(code)
    return hashlib.sha256(bytes(op for _, op, _ in iter_ops(body))).hexdigest()


def selectors_of(code: bytes) -> list[str]:
    """PUSH4 <sel> followed (within 2 ops, only DUPs in between) by EQ: the dispatcher comparison pattern."""
    ops = list(iter_ops(strip_metadata(code)))
    out = set()
    for idx, (_, op, imm) in enumerate(ops):
        if op != OP_PUSH4 or len(imm) != 4:
            continue
        for _, op2, _ in ops[idx + 1: idx + 3]:
            if op2 == OP_EQ:
                out.add(imm.hex())
                break
            if not (0x80 <= op2 <= 0x8F):
                break
    return sorted(out)


def tvm_ops(code) -> list[str]:
    """Names of TVM-only opcodes present in the runtime (empty for plain EVM code). Only meaningful for TRON code: on
    EVM these byte values are undefined opcodes and never appear in compiled code."""
    return sorted({TVM_OPS[op] for _, op, _ in iter_ops(strip_metadata(to_bytes(code))) if op in TVM_OPS})


def analyze(code_hex, tvm=False) -> dict:
    code = to_bytes(code_hex)
    if not code:
        return dict(size=0, code_hash=None, skeleton=None, selectors=[], redflags=[])
    if tvm:
        out = analyze(code_hex)
        out["tvm_ops"] = tvm_ops(code)
        out["owner_gated_puller"] = owner_gated_puller(code, out["selectors"], tvm=True)
        out["tron_markers"] = sorted(TRON_SWEEPER_SELECTORS[x] for x in out["selectors"] if x in TRON_SWEEPER_SELECTORS)
        return out
    sels = selectors_of(code)
    code_hash = "0x" + keccak(code).hex()
    exact = GEN_BAIT_RUNTIME_KECCAK.get(code_hash)
    kit = "ms_generated" if (exact or generated_bait(code, sels)) else kit_family(sels)
    return dict(size=len(code), code_hash=code_hash, skeleton=skeleton_hash(code), selectors=sels,
                redflags=[REDFLAG_SELECTORS[s] for s in sels if s in REDFLAG_SELECTORS], kit=kit,
                kit_exact=exact, kit_public=KIT_PUBLIC_RUNTIME_KECCAK.get(code_hash), ms_variant=ms_variant(code, kit, sels),
                owner_gated_puller=owner_gated_puller(code, sels), erc20_like=len(set(sels) & ERC20_SELECTORS) >= ERC20_MIN_SELECTORS,
                delegatecall=has_delegatecall(code), safe_proxy=is_safe_proxy(code), generic_proxy=is_generic_proxy(code))


def tron_sweep_abi(names) -> bool:
    """G10: a TRON contract ABI with a function named like sweep(...) (sweeper-kit marker from a public tracker)."""
    return any(n and "sweep" in n.lower() for n in (names or ()))


def log_count(code) -> int:
    """G3: number of LOG0-LOG4 opcodes (events emitted) in the runtime."""
    return sum(1 for _, op, _ in iter_ops(strip_metadata(to_bytes(code))) if 0xA0 <= op <= 0xA4)


# EIP-1967 implementation / admin / beacon slots and the EIP-1822 (UUPS) proxiable slot
PROXY_SLOTS = tuple(bytes.fromhex(h) for h in (
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    "c5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"))


def is_generic_proxy(code) -> bool:
    """Standard upgradeable proxy (EIP-1967 / UUPS): DELEGATECALL plus a standard slot constant. Its skeleton is the
    library's, shared by thousands of unrelated contracts, so it must never place the contract in a code family."""
    code = to_bytes(code)
    return bool(code) and any(s in code for s in PROXY_SLOTS) and has_delegatecall(code)


def has_delegatecall(code) -> bool:
    """W4: the runtime contains DELEGATECALL (0xf4) as an opcode (not inside PUSH data)."""
    return any(op == OP_DELEGATECALL for _, op, _ in iter_ops(strip_metadata(to_bytes(code))))


def is_safe_proxy(code) -> bool:
    """W6: Safe (Gnosis Safe) proxy runtime (1.3.0 / 1.4.1 ProxyFactory): < 300 B, compares the call selector with
    masterCopy() 0xa619486e as a PUSH32 word and forwards everything else with DELEGATECALL to the singleton in slot 0."""
    code = to_bytes(code)
    return 0 < len(code) < 300 and bytes.fromhex("7fa619486e") in code and has_delegatecall(code)


def kit_family(selectors):
    """Kit fingerprint from the dispatcher selector set (kit notes): `trusty_v1` (N2, the kit's 2023 public pass-through
    contract) = Fee(address) + getFee() + changePercentage(uint8) + >=3 bait(address); `ms_drainer` = >=1 bait(address)
    + >=2 companion selectors; `verify_account` = >=2 of Verify20 / Verify10 / withdrawAllTrxTo; `ms_new` (K1) = >=3 MS_NEW 5-arg baits
    + >=2 of its companions (changePercentage, claimSalary, disableSalary, enableSalary, salaryStatus, setReceiver);
    `owner_collector` (K9) = >=5 of the 6 OwnerCollector selectors incl. collectToOwner or collectAllFrom;
    `buytron_swap_trx` / `buytron_swap_proxy` = the exact dispatcher of the public TRON "buytron" kit contracts. None
    otherwise. The code-trait family `ms_generated` (K2) is decided in analyze()."""
    s = set(selectors)
    if frozenset(s) in BUYTRON_FAMILIES:
        return BUYTRON_FAMILIES[frozenset(s)]
    if len(s & set(MS_NEW_SELECTORS)) >= MS_NEW_MIN_BAIT and len(s & set(MS_NEW_COMPANION_SELECTORS)) >= MS_NEW_MIN_COMPANION:
        return "ms_new"
    if set(TRUSTY_V1_SELECTORS) <= s and len(s & set(BAIT_ADDR_SELECTORS)) >= TRUSTY_V1_MIN_BAIT:
        return "trusty_v1"
    if len(s & set(BAIT_ADDR_SELECTORS)) >= MS_MIN_BAIT and len(s & set(MS_COMPANION_SELECTORS)) >= MS_MIN_COMPANION:
        return "ms_drainer"
    if len(s & set(VERIFY_ACCOUNT_SELECTORS)) >= VERIFY_ACCOUNT_MIN:
        return "verify_account"
    oc = s & set(OWNER_COLLECTOR_SELECTORS)
    if len(oc) >= OWNER_COLLECTOR_MIN and oc & {"d253abea", "130cbae0"}:
        return "owner_collector"
    return None


def generated_bait(code, sels=None) -> bool:
    """K2 code traits of the MS Contract Generator bait (kit notes K1-K14): runtime 850-950 B, exactly one PUSH4
    and it is one of the 16 no-arg bait selectors (= the whole dispatcher), the 2300-gas transfer stipend PUSH2 0x08fc
    at least twice, PUSH1 0x64 (percent divisor), >= 2 CALLs and no SSTORE in the runtime (receivers are set by the
    constructor only)."""
    code = to_bytes(code)
    if not (GEN_BAIT_SIZE[0] <= len(code) <= GEN_BAIT_SIZE[1]):
        return False
    ops = list(iter_ops(strip_metadata(code)))
    push4 = [imm.hex() for _, op, imm in ops if op == OP_PUSH4]
    if len(push4) != 1 or push4[0] not in GEN_BAIT_SELECTORS:
        return False
    if sels is not None and set(sels) - set(push4):
        return False
    stipend = sum(1 for _, op, imm in ops if op == OP_PUSH2 and imm == bytes.fromhex("08fc"))
    pct = any(op == OP_PUSH1 and imm == bytes.fromhex("64") for _, op, imm in ops)
    calls = sum(1 for _, op, _ in ops if op == OP_CALL)
    return stipend >= 2 and pct and calls >= 2 and not any(op == OP_SSTORE for _, op, _ in ops)


def ms_variant(code, kit, sels):
    """K3: an `ms_drainer` contract without any storage write in its runtime (no balance mapping, no withdraw) is the
    pass-through variant `Claim(address) payable { payable(arg).transfer(msg.value); }`; with storage writes it is the
    multi-tenant variant (balance[arg] += msg.value, customers withdraw later)."""
    if kit != "ms_drainer":
        return None
    ops = {op for _, op, _ in iter_ops(strip_metadata(to_bytes(code)))}
    return "multitenant" if OP_SSTORE in ops else "passthrough"


_MASK20 = bytes([0xFF]) * 20
_ERC20_DISPATCH = {"a9059cbb", "23b872dd", "70a08231"}   # transfer / transferFrom / balanceOf: the contract IS a token
OWNER_WINDOW = 24            # ops between SLOAD, CALLER and EQ for `require(msg.sender == owner)`
PULLER_MAX_CODE = 6144
PULLER_MAX_SELECTORS = 10


def _owner_check(ops):
    """CALLER compared (EQ) with a storage value (SLOAD) inside a short op window, in either order."""
    pos = {OP_SLOAD: -10 ** 9, OP_CALLER: -10 ** 9}
    for i, (_, op, _) in enumerate(ops):
        if op in pos:
            pos[op] = i
        elif op == OP_EQ and i - pos[OP_SLOAD] <= OWNER_WINDOW and i - pos[OP_CALLER] <= OWNER_WINDOW:
            return True
    return False


def owner_gated_puller(code, sels=None, tvm=False) -> bool:
    """R-A2 static heuristic (case notes case A): a small non-token contract that
    (1) has an owner check (CALLER compared with SLOAD(slot)), (2) builds an external transferFrom call (PUSH4 0x23b872dd
    that is NOT a dispatcher comparison) with CALL, (3) reads calldata, and (4) carries no hard-coded address (no PUSH20
    other than the 0xff..ff mask, no PUSH32 holding a left-padded address = immutable): token, from, to and amount can
    only come from the call parameters. Best effort; T3 alone. tvm=True: TRON code, where CALLTOKEN (a CALL that also
    moves a TRC-10 token) counts as the external call."""
    code = to_bytes(code)
    if not code or len(code) > PULLER_MAX_CODE:
        return False
    sels = set(sels if sels is not None else selectors_of(code))
    if not sels or len(sels) > PULLER_MAX_SELECTORS or sels & _ERC20_DISPATCH:
        return False
    ops = list(iter_ops(strip_metadata(code)))
    have = {op for _, op, _ in ops}
    if tvm and OP_CALLTOKEN in have:
        have.add(OP_CALL)
    if not {OP_CALL, OP_CALLDATALOAD, OP_CALLER, OP_SLOAD} <= have:
        return False
    tf = bytes.fromhex(SEL_TRANSFER_FROM)
    builds_tf = False
    for idx, (_, op, imm) in enumerate(ops):
        if op == OP_PUSH20 and imm != _MASK20:
            return False
        if op == OP_PUSH32 and len(imm) == 32 and imm[:12] == bytes(12) and any(imm[12:]) and imm[12:] != _MASK20:
            return False
        if op == OP_PUSH4 and imm == tf:
            nxt = [o for _, o, _ in ops[idx + 1: idx + 3]]
            if OP_EQ not in nxt:
                builds_tf = True
    return builds_tf and _owner_check(ops)


def is_delegated_eoa(code_hex) -> bool:
    """EIP-7702 delegation indicator: 0xef0100 || address (23 bytes)."""
    c = (code_hex or "0x")
    return c.lower().startswith("0xef0100") and len(c) == 2 + 46


def delegate_of(code_hex):
    return "0x" + code_hex[8:48].lower() if is_delegated_eoa(code_hex) else None


def family_id(skeleton: str) -> str:
    return "f_" + skeleton[:6]


def jaccard(a, b) -> float:
    a, b = set(a), set(b)
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def match_family(skeleton, selectors, size, seeds):
    """seeds: iterable of dicts {skeleton, selectors, size}. Exact skeleton match or selector Jaccard >= 0.8
    (>= 3 selectors on both sides, code >= 100 B so EIP-1167 minimal proxies never form a family).
    Returns (family_id, 'skeleton'|'selectors', seed_index) or None."""
    if not skeleton or (size or 0) < FAMILY_MIN_CODE:
        return None
    best = None
    for i, s in enumerate(seeds):
        if (s.get("size") or 0) < FAMILY_MIN_CODE or not s.get("skeleton"):
            continue
        if s["skeleton"] == skeleton:
            return family_id(s["skeleton"]), "skeleton", i
        if len(selectors) >= FAMILY_MIN_SELECTORS and len(s["selectors"]) >= FAMILY_MIN_SELECTORS:
            j = jaccard(selectors, s["selectors"])
            if j >= FAMILY_JACCARD and (best is None or j > best[0]):
                best = (j, family_id(s["skeleton"]), i)
    if best:
        return best[1], "selectors", best[2]
    return None


def is_forwarder_7702(code_hex) -> bool:
    """G11: EIP-7702 'Forwarder' delegate: dispatcher with initialize(address) and destination() (forwards native value to
    the address stored by initialize). Wallet implementations have far richer dispatchers."""
    code = to_bytes(code_hex)
    if not code or is_delegated_eoa(code_hex):
        return False
    sels = set(selectors_of(code))
    return FORWARDER_7702_SELECTORS <= sels and len(sels) <= 8


def is_sweeper_code(code_hex) -> bool:
    """D6 heuristic (best effort): small contract with CALLVALUE + PUSH20 + CALL and no SLOAD at all
    (no storage-held owner, so no owner-gated check)."""
    code = to_bytes(code_hex)
    if not code or len(code) >= SWEEPER_MAX_CODE:
        return False
    ops = {op for _, op, _ in iter_ops(strip_metadata(code))}
    return OP_CALLVALUE in ops and OP_PUSH20 in ops and OP_CALL in ops and OP_SLOAD not in ops
