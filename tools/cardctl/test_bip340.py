"""
Tests for the pure-Python BIP-340 verifier in bip340.py.

This verifier is what `cardctl selftest` uses to decide whether a signature
coming off real silicon is valid. If it is wrong, selftest either passes a
broken card or rejects a good one — so it gets tested three independent ways:

1. Canonical BIP-340 test vectors from the specification (must verify).
2. Round-trip against a reference BIP-340 *signer* implemented here from the
   spec pseudocode, over random keys and messages. An independent signer is a
   stronger check than replaying fixed vectors, because it exercises the whole
   (k, e, s) relationship rather than four precomputed answers.
3. Mutation: take a signature that verifies, corrupt one byte of the signature,
   the message, or the public key, and require rejection. A verifier that
   returns True unconditionally passes (1) and (2) but fails this.

Run:  python3 -m pytest test_bip340.py -q     (or: python3 test_bip340.py)
"""

import hashlib
import secrets

import bip340
from bip340 import G, N, _point_mul, tagged_hash

# ── 1. Canonical vectors (BIP-340 test-vectors.csv, verifying cases) ──────────
VECTORS = [
    (
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ),
    (
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    ),
    (
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
        "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    ),
    (
        # Fails if the message is reduced modulo p or n.
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
        "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
    ),
]


def test_canonical_vectors():
    for pk, msg, sig in VECTORS:
        assert bip340.verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig)), \
            f"canonical vector failed: pk={pk[:16]}…"


# ── 2. Reference signer (BIP-340 default signing) ────────────────────────────
def reference_sign(seckey: int, msg: bytes, aux: bytes) -> tuple:
    """Returns (x_only_pubkey, signature) per the BIP-340 reference algorithm."""
    assert 0 < seckey < N
    point = _point_mul(G, seckey)
    d = seckey if point[1] % 2 == 0 else N - seckey
    px = point[0].to_bytes(32, "big")

    t = d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")
    rand = tagged_hash("BIP0340/nonce", t.to_bytes(32, "big") + px + msg)
    k0 = int.from_bytes(rand, "big") % N
    assert k0 != 0

    big_r = _point_mul(G, k0)
    k = k0 if big_r[1] % 2 == 0 else N - k0
    rx = big_r[0].to_bytes(32, "big")

    e = int.from_bytes(tagged_hash("BIP0340/challenge", rx + px + msg), "big") % N
    return px, rx + ((k + e * d) % N).to_bytes(32, "big")


def test_roundtrip_against_reference_signer():
    for _ in range(20):
        seckey = secrets.randbelow(N - 1) + 1
        msg = secrets.token_bytes(32)
        px, sig = reference_sign(seckey, msg, secrets.token_bytes(32))
        assert bip340.verify(px, msg, sig), "reference signature rejected"


def test_signature_does_not_verify_under_a_different_key():
    msg = secrets.token_bytes(32)
    px_a, sig_a = reference_sign(secrets.randbelow(N - 1) + 1, msg, b"\x00" * 32)
    px_b, _ = reference_sign(secrets.randbelow(N - 1) + 1, msg, b"\x00" * 32)
    assert bip340.verify(px_a, msg, sig_a)
    assert not bip340.verify(px_b, msg, sig_a), "signature verified under the wrong key"


# ── 3. Mutation — a verifier that always returns True must fail these ────────
def _flip(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


def test_mutations_are_rejected():
    seckey = secrets.randbelow(N - 1) + 1
    msg = secrets.token_bytes(32)
    px, sig = reference_sign(seckey, msg, secrets.token_bytes(32))
    assert bip340.verify(px, msg, sig)

    for i in (0, 31, 32, 63):
        assert not bip340.verify(px, msg, _flip(sig, i)), f"corrupt sig byte {i} accepted"
    for i in (0, 31):
        assert not bip340.verify(px, _flip(msg, i), sig), f"corrupt msg byte {i} accepted"
        assert not bip340.verify(_flip(px, i), msg, sig), f"corrupt pubkey byte {i} accepted"


def test_out_of_range_components_are_rejected():
    px, sig = reference_sign(secrets.randbelow(N - 1) + 1, b"\x11" * 32, b"\x00" * 32)
    msg = b"\x11" * 32
    # s >= n
    assert not bip340.verify(px, msg, sig[:32] + N.to_bytes(32, "big"))
    # r >= p
    assert not bip340.verify(px, msg, bip340.P.to_bytes(32, "big") + sig[32:])
    # wrong lengths
    assert not bip340.verify(px, msg, sig[:63])
    assert not bip340.verify(px[:31], msg, sig)


def test_x_only_strips_compressed_prefix():
    raw = secrets.token_bytes(32)
    assert bip340.x_only(b"\x02" + raw) == raw
    assert bip340.x_only(b"\x03" + raw) == raw
    assert bip340.x_only(raw) == raw


def test_lift_x_rejects_non_curve_points():
    # x = 0 is not on secp256k1 (0^3 + 7 = 7 is not a QR mod p)
    assert bip340.lift_x(0) is None
    assert bip340.lift_x(bip340.P) is None
    # A known-good x from vector 1 must lift, with even y.
    point = bip340.lift_x(int(VECTORS[1][0], 16))
    assert point is not None and point[1] % 2 == 0


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL  {name}: {exc}")
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    raise SystemExit(1 if failures else 0)
