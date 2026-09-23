#!/usr/bin/env python3
"""
hwtest_65byte_pubkey.py — the hardware check behind section 8 of
docs/HARDWARE_TEST_REPORT_2026-09-01.j3r452.md.

At commit afe1081 the applet sent `ECPublicKey.getW()` straight to the host,
and on an NXP JCOP4.5 J3R452 that is a 65-byte uncompressed point. `cardctl
selftest` and `cardctl sign` then died in `bip340.x_only()` before verifying
anything, so the unmodified tool could not tell a wrong *encoding* from wrong
*crypto*. This script separates the two: it normalises the key on the host,
checks the point is on secp256k1, and only then runs the same sign/verify and
nonce-freshness rounds `selftest` would have run.

It does nothing `cardctl sign` does not already do to the card: SELECT,
GET_PUBKEY, and SIGN_ARBITRARY over random messages. No proof is written or
spent, no PIN is touched, and the card is never locked.

Run from tools/cardctl with the same venv and reader index as cardctl:

    python hwtest_65byte_pubkey.py -r 1

The output lines are the ones quoted verbatim in the report. Exit status is 0
only if every check passed. The applet-side fix (#23) makes GET_PUBKEY return
33 bytes, which this script also accepts, so it stays a valid post-fix check.
"""

import argparse
import secrets
import sys

import bip340
import cardctl


def point_on_curve(x: int, y: int) -> bool:
    """True iff (x, y) satisfies y^2 = x^3 + 7 over the secp256k1 field."""
    if not (0 <= x < bip340.P and 0 <= y < bip340.P):
        return False
    return (y * y - (pow(x, 3, bip340.P) + 7)) % bip340.P == 0


def normalize_pubkey(pk: bytes) -> bytes:
    """
    Accept a 33-byte compressed or 65-byte uncompressed secp256k1 point and
    return the 33-byte compressed form the spec requires. Raises ValueError for
    anything that is not a valid point in one of those two encodings.
    """
    if len(pk) == 33 and pk[0] in (0x02, 0x03):
        if bip340.lift_x(int.from_bytes(pk[1:], "big")) is None:
            raise ValueError("compressed pubkey x is not on secp256k1")
        return bytes(pk)
    if len(pk) == 65 and pk[0] == 0x04:
        x = int.from_bytes(pk[1:33], "big")
        y = int.from_bytes(pk[33:65], "big")
        if not point_on_curve(x, y):
            raise ValueError("uncompressed pubkey is not on secp256k1")
        return bytes([0x02 if y % 2 == 0 else 0x03]) + pk[1:33]
    raise ValueError(f"not a secp256k1 pubkey encoding: {len(pk)} bytes")


def run(card: "cardctl.Card", rounds: int, out=sys.stdout) -> bool:
    """Section 8, steps 1-6. Returns True iff every check passed."""
    def report(name: str, ok: bool) -> bool:
        print(f"{name}: {'PASS' if ok else 'FAIL'}", file=out)
        return ok

    all_ok = True

    pk = card.get_pubkey()
    print(f"GET_PUBKEY raw ({len(pk)} bytes): {pk.hex()}", file=out)

    if len(pk) == 65 and pk[0] == 0x04:
        x = int.from_bytes(pk[1:33], "big")
        y = int.from_bytes(pk[33:65], "big")
        on_curve = point_on_curve(x, y)
        print(f"Public key point on secp256k1: {on_curve}", file=out)
        all_ok &= on_curve

    try:
        compressed = normalize_pubkey(pk)
    except ValueError as exc:
        print(f"Public key normalisation: FAIL ({exc})", file=out)
        print("MANUAL HARDWARE SELFTEST: FAIL", file=out)
        return False
    print(f"Compressed pubkey: {compressed.hex()}", file=out)
    pk_x = compressed[1:]

    # Steps 4-5: fresh random messages, each signature verified under BIP-340
    # with the repository's own verifier.
    for i in range(rounds):
        msg = secrets.token_bytes(32)
        sig = card.sign(msg)
        all_ok &= report(
            f"SIGN_ARBITRARY + BIP-340 verify [{i + 1}/{rounds}]",
            bip340.verify(pk_x, msg, sig),
        )

    # Step 6: the same message twice. Both must verify and R must differ —
    # a deterministic R across identical messages is a private-key leak
    # waiting for a fault injector.
    msg = secrets.token_bytes(32)
    sig1 = card.sign(msg)
    sig2 = card.sign(msg)
    all_ok &= report("Identical-message signature #1 verifies", bip340.verify(pk_x, msg, sig1))
    all_ok &= report("Identical-message signature #2 verifies", bip340.verify(pk_x, msg, sig2))
    all_ok &= report("Fresh nonce across identical messages", sig1[:32] != sig2[:32])

    print(f"MANUAL HARDWARE SELFTEST: {'PASS' if all_ok else 'FAIL'}", file=out)
    return all_ok


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("-r", "--reader", type=int, default=0, help="reader index (default 0)")
    p.add_argument("-v", "--verbose", action="store_true", help="log APDUs to stderr")
    p.add_argument("--rounds", type=int, default=3, help="sign/verify rounds (default 3)")
    args = p.parse_args()

    card = cardctl.Card(reader_index=args.reader, verbose=args.verbose)
    card.select()
    return 0 if run(card, args.rounds) else 1


if __name__ == "__main__":
    sys.exit(main())
