from drainerwatch import bytecode as bc
from drainerwatch.auth7702 import auth_digest, authority_of, pub_to_address, recover, sign, _mul, G
from drainerwatch.constants import REDFLAG_SELECTORS
from drainerwatch.tokens import is_spoof_symbol
from drainerwatch.util import keccak, selector


def dispatcher(sels, const=b"\x00\x01"):
    """PUSH1 0x80 PUSH1 0x40 MSTORE, then DUP1 PUSH4 sel EQ PUSH2 const JUMPI per selector."""
    code = bytes([0x60, 0x80, 0x60, 0x40, 0x52])
    for s in sels:
        code += bytes([0x80, 0x63]) + bytes.fromhex(s) + bytes([0x14, 0x61]) + const + bytes([0x57])
    return code + bytes([0x00]) * 120          # pad to > 100 bytes


def meta(payload=b"ipfs" + b"\x12\x20" + b"\x01" * 32):
    blob = b"\xa2\x64" + payload + b"\x64solc\x43\x00\x08\x14"
    return blob + len(blob).to_bytes(2, "big")


def test_skeleton_ignores_push_immediates_and_metadata():
    base = dispatcher(["a9059cbb", "70a08231"], const=b"\x00\x10")
    other = dispatcher(["deadbeef", "cafebabe"], const=b"\x7f\xff")     # other PUSH4/PUSH2 constants
    assert bc.skeleton_hash(base) == bc.skeleton_hash(other)
    assert bc.skeleton_hash(base + meta()) == bc.skeleton_hash(base + meta(b"ipfs" + b"\x12\x20" + b"\x02" * 32))
    assert bc.skeleton_hash(base + meta()) == bc.skeleton_hash(base)
    longer = dispatcher(["a9059cbb", "70a08231", "095ea7b3"])
    assert bc.skeleton_hash(base) != bc.skeleton_hash(longer)           # different opcode stream


def test_strip_metadata_requires_marker():
    c = bytes(range(1, 60)) + (10).to_bytes(2, "big")                     # trailing length but no CBOR/ipfs
    assert bc.strip_metadata(c) == c
    code = dispatcher(["a9059cbb"])
    assert bc.strip_metadata(code + meta()) == code


def test_push_data_is_not_decoded_as_opcodes():
    # PUSH2 holding 0x5757 (JUMPI bytes) must not create extra ops
    ops = [op for _, op, _ in bc.iter_ops(bytes([0x61, 0x57, 0x57, 0x00]))]
    assert ops == [0x61, 0x00]


def test_selectors_and_redflags():
    claim = selector("Claim()")
    code = dispatcher([claim, "a9059cbb", selector("SecurityUpdate()")])
    info = bc.analyze("0x" + code.hex())
    assert set(info["selectors"]) == {claim, "a9059cbb", selector("SecurityUpdate()")}
    assert set(info["redflags"]) == {"Claim()", "SecurityUpdate()"}
    assert REDFLAG_SELECTORS[claim] == "Claim()"
    # a PUSH4 not followed by EQ is not a selector
    assert bc.selectors_of(bytes([0x63, 1, 2, 3, 4, 0x50, 0x00])) == []


def test_family_match():
    seed = bc.analyze("0x" + dispatcher(["11111111", "22222222", "33333333", "44444444", "55555555"]).hex())
    seeds = [dict(skeleton=seed["skeleton"], selectors=set(seed["selectors"]), size=seed["size"])]
    same = bc.analyze("0x" + dispatcher(["11111111", "22222222", "33333333", "44444444", "55555555"], b"\x09\x09").hex())
    assert bc.match_family(same["skeleton"], same["selectors"], same["size"], seeds)[1] == "skeleton"
    # sixth selector added: skeleton differs, Jaccard 5/6 = 0.83 >= 0.8
    near = bc.analyze("0x" + dispatcher(["11111111", "22222222", "33333333", "44444444", "55555555", "66666666"]).hex())
    m = bc.match_family(near["skeleton"], near["selectors"], near["size"], seeds)
    assert m and m[1] == "selectors" and m[0] == bc.family_id(seed["skeleton"])
    far = bc.analyze("0x" + dispatcher(["11111111", "22222222", "aaaaaaaa", "bbbbbbbb", "cccccccc", "dddddddd"]).hex())
    assert bc.match_family(far["skeleton"], far["selectors"], far["size"], seeds) is None


def test_minimal_proxy_never_forms_a_family():
    proxy = bytes.fromhex("363d3d373d3d3d363d73" + "ab" * 20 + "5af43d82803e903d91602b57fd5bf3")
    p = bc.analyze("0x" + proxy.hex())
    seeds = [dict(skeleton=p["skeleton"], selectors=set(), size=p["size"])]
    assert bc.match_family(p["skeleton"], p["selectors"], p["size"], seeds) is None


def test_sweeper_heuristic():
    sweeper = bytes([0x34, 0x73]) + b"\x11" * 20 + bytes([0x60, 0x00, 0xF1, 0x00])
    assert bc.is_sweeper_code("0x" + sweeper.hex())
    assert not bc.is_sweeper_code("0x" + (sweeper + bytes([0x54])).hex())          # SLOAD: owner-gated
    assert not bc.is_sweeper_code("0x" + (sweeper + b"\x00" * 1100).hex())         # too big
    assert not bc.is_sweeper_code("0x" + bytes([0x34, 0xF1]).hex())                # no PUSH20


def test_delegation_designator():
    d = "0xef0100" + "ab" * 20
    assert bc.is_delegated_eoa(d) and bc.delegate_of(d) == "0x" + "ab" * 20
    assert not bc.is_delegated_eoa("0x6080")


def test_spoof_symbols():
    assert is_spoof_symbol("U⁯S⁯DΤ", False)       # invisible chars + greek tau
    assert is_spoof_symbol("U5DT", False)                          # one edit from USDT, non-canonical token
    assert not is_spoof_symbol("USDT", True)                       # canonical contract
    assert not is_spoof_symbol("PEPE", False)
    assert not is_spoof_symbol(None, False)


def test_eip7702_recover_roundtrip():
    priv, k = 0xC0FFEE1234567, 0x1234567890ABCDEF
    pub = _mul(priv, G)
    me = pub_to_address(pub)
    delegate = "0x" + "cd" * 20
    digest = auth_digest(1, delegate, 7)
    r, s, rec = sign(digest, priv, k)
    assert pub_to_address(recover(digest, r, s, rec)) == me
    auth = dict(chainId=hex(1), address=delegate, nonce=hex(7), yParity=hex(rec), r=hex(r), s=hex(s))
    assert authority_of(auth) == me
    assert authority_of(dict(auth, nonce=hex(8))) != me             # different tuple, different signer
    assert keccak(b"")[:4].hex() == "c5d24601"
