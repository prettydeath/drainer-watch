"""EIP-7702: recover the authority (delegator) of an authorization tuple. Pure Python secp256k1 (no extra deps).

authority = ecrecover(keccak(0x05 || rlp([chain_id, address, nonce])), yParity, r, s)"""
from .util import hx, keccak

P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0]:
        if (a[1] + b[1]) % P == 0:
            return None
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def recover(msg_hash: bytes, r: int, s: int, rec: int):
    """Public key point or None."""
    if not (1 <= r < N and 1 <= s < N) or rec not in (0, 1):
        return None
    y2 = (pow(r, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if y % 2 != rec:
        y = P - y
    e = int.from_bytes(msg_hash, "big")
    rinv = pow(r, -1, N)
    q = _add(_mul(s * rinv % N, (r, y)), _mul((-e * rinv) % N, G))
    return q


def pub_to_address(q) -> str:
    return "0x" + keccak(q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big"))[12:].hex()


def sign(msg_hash: bytes, priv: int, k: int):
    """Deterministic-k signer used by tests only: returns (r, s, recid)."""
    R = _mul(k, G)
    r = R[0] % N
    s = pow(k, -1, N) * (int.from_bytes(msg_hash, "big") + r * priv) % N
    rec = R[1] & 1
    if s > N // 2:
        s = N - s
        rec ^= 1
    return r, s, rec


def rlp_item(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _len_prefix(len(b), 0x80) + b


def _len_prefix(n, off):
    if n < 56:
        return bytes([off + n])
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(nb)]) + nb


def rlp_int(n: int) -> bytes:
    return rlp_item(b"" if n == 0 else n.to_bytes((n.bit_length() + 7) // 8, "big"))


def rlp_list(items: list[bytes]) -> bytes:
    body = b"".join(items)
    return _len_prefix(len(body), 0xC0) + body


def auth_digest(chain_id: int, address: str, nonce: int) -> bytes:
    payload = rlp_list([rlp_int(chain_id), rlp_item(bytes.fromhex(address[2:])), rlp_int(nonce)])
    return keccak(b"\x05" + payload)


def authority_of(auth: dict):
    """auth: one entry of tx.authorizationList (hex strings). Returns lowercase address or None."""
    try:
        rec = hx(auth.get("yParity", auth.get("v")))
        q = recover(auth_digest(hx(auth["chainId"]), auth["address"].lower(), hx(auth["nonce"])),
                    hx(auth["r"]), hx(auth["s"]), rec)
        return pub_to_address(q) if q else None
    except (KeyError, ValueError, TypeError):
        return None
