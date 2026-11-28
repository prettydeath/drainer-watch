"""Contract code classifier: the primary tiering signal (precision audit 2026-11-28).

classify() sorts a subject's code into one of
  drainer_code  a kit fingerprint, a kit function / contract name, or a tiny owner-gated puller (a contract whose only
                external entries besides ownership pull tokens of third parties: transferFrom(token, from, to, amount)
                or a batch of it, no user-facing logic);
  poisoner      the address-poisoning batcher transferFrom(address[],address[],address[],uint256[]) + events() (or a
                contract named like one): poisoning, not a drainer;
  legit_code    a known service by its verified / TRON contract name (forwarders, Safe, 4337 accounts / paymasters /
                7702 delegates, settlers, routers, position managers, splitters, vaults, bridges / OFT), an Etherscan-
                verified proxy implementation or a Safe singleton proxy;
  tiny          an unnamed small contract (<= TINY_MAX_SIZE bytes, <= TINY_MAX_SELECTORS entries, not an ERC-20): drainer
                shaped, but without a pull dispatcher or a kit name;
  generic       any other contract;
  eoa           no code (or a 23-byte EIP-7702 delegation designator).
Works on the stored metadata (size, dispatcher selectors, names, bytecode flags), so every stored subject can be
re-classified on every roll-up. Selector names come from the built-in kit tables and the cached signature table
(sig_names, filled by famname): no live lookups here.
"""
import re

from . import constants as K

TINY_MAX_SIZE = 6144
TINY_MAX_SELECTORS = 8
DELEGATION_SIZE = 23                    # 0xef0100 || address: an EIP-7702 delegated EOA

SEL_POISON_BATCH = K.selector("transferFrom(address[],address[],address[],uint256[])")
SEL_EVENTS = K.selector("events()")
# function names of drainer kits (exact base name; the capitalised payable bait names are case-sensitive on purpose:
# claim(uint256) of a staking contract is not Claim(address) of a bait)
KIT_FUNCTIONS = {"Verify20", "Verify10", "controlAndTransferToken", "transferFromToken", "pullFunds", "claimToken",
                 "drainWallet", "SecurityUpdate", "Connect", "Claim", "ClaimReward", "ClaimRewards"}
KIT_CONTRACT_RE = re.compile(r"^(walletverifier|netkiller\w*|verifyaccount|tronverification|drainer\w*)$", re.I)
POISONER_NAME_RE = re.compile(r"(addresspoisoner|dirtyphisher)", re.I)
LEGIT_NAME_RE = re.compile(
    r"(forwarder|erc2771|gnosissafe|^safe(proxy|l2)?\b|safeproxy|simpleaccount|^account$|delegator|^delegate|"
    r"7702delegate|paymaster|entrypoint|settler|router|positionmanager|splitter|vault|bridge|^oft|oftadapter|"
    r"multicall|erc1967proxy|transparentupgradeableproxy|beaconproxy|proxyadmin|timelock|permit2|aggregat)", re.I)
ERC20_CORE = {"a9059cbb", "23b872dd", "095ea7b3", "70a08231", "18160ddd", "dd62ed3e"}
OWNERSHIP = {"8da5cb5b", "f2fde38b", "715018a6", "893d20e8"}       # owner(), transferOwnership, renounce, getOwner


def builtin_names():
    """selector -> function signature from the kit / rule tables in constants (no network)."""
    out = {}
    for v in vars(K).values():
        if isinstance(v, dict):
            for s, nm in v.items():
                if isinstance(s, str) and isinstance(nm, str) and len(s.replace("0x", "")) == 8 and "(" in nm:
                    out[s.replace("0x", "")] = nm
    return out


_BUILTIN = None


def sel_names(conn=None):
    """selector -> signature: built-in tables plus the cached sig_names table (if present)."""
    global _BUILTIN
    if _BUILTIN is None:
        _BUILTIN = builtin_names()
    out = {}
    if conn is not None:
        try:
            out = {r[0]: r[1] for r in conn.execute("SELECT selector,name FROM sig_names WHERE name != ''")}
        except Exception:  # noqa: BLE001 - table created by famname
            out = {}
    out.update(_BUILTIN)
    return out


def _base(sig):
    return (sig or "").split("(", 1)[0]


def is_poisoner(selectors, names=()):
    s = set(selectors or ())
    return ({SEL_POISON_BATCH, SEL_EVENTS} <= s) or any(n and POISONER_NAME_RE.search(n) for n in names or ())


def classify(size, selectors=(), names=(), abi=(), flags=None, sigs=None):
    """-> one of drainer_code / poisoner / legit_code / tiny / generic / eoa.
    size: runtime size (0 / None = no code); selectors: dispatcher selectors (hex, no 0x); names: contract names
    (Etherscan verified name, TRON getcontract name); abi: TRON ABI function names when known; flags: dict with
    kit / kit_exact / kit_public / redflags / puller / verified / proxy / safe_proxy; sigs: selector -> signature."""
    f = flags or {}
    sels = [s.replace("0x", "") for s in (selectors or ())]
    names = [n for n in (names or ()) if n]
    if not size or size == DELEGATION_SIZE:
        return "eoa"
    if is_poisoner(sels, names):
        return "poisoner"
    fn = {_base((sigs or {}).get(s)) for s in sels} | {_base(a) for a in abi or ()}
    fn.discard("")
    if f.get("kit") and f.get("kit") != "tron_sweeper" or f.get("kit_exact") or f.get("kit_public") or f.get("redflags"):
        return "drainer_code"
    if fn & KIT_FUNCTIONS and size <= TINY_MAX_SIZE * 2 or any(KIT_CONTRACT_RE.match(n) for n in names):
        return "drainer_code"
    erc20 = len(set(sels) & ERC20_CORE) >= 4
    small = size <= TINY_MAX_SIZE and len(sels) <= TINY_MAX_SELECTORS and not erc20
    if f.get("puller") and small:
        return "drainer_code"           # owner-gated parametric transferFrom(token, from, to, amount) dispatcher
    if any(LEGIT_NAME_RE.search(n) for n in names) or f.get("safe_proxy"):
        return "legit_code"
    if f.get("proxy") and f.get("verified"):
        return "legit_code"             # proxy of an Etherscan-verified implementation
    if small and sels:
        return "tiny"
    return "generic"
