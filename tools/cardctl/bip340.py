"""
Pure-Python BIP-340 Schnorr verification.

Deliberately dependency-free. The whole point of this tool is to answer one
question on the day a physical card arrives — *does the signature this card
just produced actually verify?* — and that answer is worth much less if it
depends on a native library that may not build on the machine in front of you.
Speed is irrelevant here: we verify one signature per tap, not thousands.

Cross-checked against the BIP-340 reference test vectors in test_bip340.py.
"""

import hashlib
from typing import Optional, Tuple

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = Optional[Tuple[int, int]]


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """SHA256(SHA256(tag) || SHA256(tag) || msg) — BIP-340 §Design."""
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and p1[1] != p2[1]:
        return None  # P + (-P) = point at infinity
    if p1 == p2:
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], P - 2, P)) % P
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], P - 2, P)) % P
    x3 = (lam * lam - p1[0] - p2[0]) % P
    return (x3, (lam * (p1[0] - x3) - p1[1]) % P)


def _point_mul(p: Point, k: int) -> Point:
    r: Point = None
    for i in range(256):
        if (k >> i) & 1:
            r = _point_add(r, p)
        p = _point_add(p, p)
    return r


def lift_x(x: int) -> Point:
    """BIP-340 lift_x: the point with x-coordinate `x` and EVEN y, if it exists."""
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None  # x is not on the curve
    return (x, y if y % 2 == 0 else P - y)


def verify(pubkey_x: bytes, msg: bytes, sig: bytes) -> bool:
    """
    Verify a BIP-340 signature.

    :param pubkey_x: 32-byte x-only public key. If you have the card's 33-byte
                     compressed key, pass ``pubkey[1:]`` — BIP-340 keys are
                     x-only and implicitly even-y, which is exactly the
                     normalisation the applet applies before signing.
    :param msg:      32-byte message
    :param sig:      64-byte signature, R.x || s
    """
    if len(pubkey_x) != 32 or len(msg) != 32 or len(sig) != 64:
        return False

    point = lift_x(int.from_bytes(pubkey_x, "big"))
    if point is None:
        return False

    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= P or s >= N:
        return False

    e = int.from_bytes(
        tagged_hash("BIP0340/challenge", sig[:32] + pubkey_x + msg), "big"
    ) % N

    # R = s*G - e*P
    big_r = _point_add(_point_mul(G, s), _point_mul(point, N - e))
    if big_r is None or big_r[1] % 2 != 0 or big_r[0] != r:
        return False
    return True


def x_only(compressed_pubkey: bytes) -> bytes:
    """Strip the 02/03 prefix from a 33-byte compressed key to get x-only."""
    if len(compressed_pubkey) == 33 and compressed_pubkey[0] in (0x02, 0x03):
        return compressed_pubkey[1:]
    if len(compressed_pubkey) == 32:
        return compressed_pubkey
    raise ValueError(f"not a compressed secp256k1 pubkey: {len(compressed_pubkey)} bytes")
