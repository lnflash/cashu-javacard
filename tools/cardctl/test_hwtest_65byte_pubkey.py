#!/usr/bin/env python3
"""
Card-free tests for hwtest_65byte_pubkey.py.

The script's card-facing part is a handful of APDUs already covered by
test_apdu.py. What is worth pinning here is the host-side normalisation it
adds: that the exact 65-byte key the J3R452 returned in the 2026-09-01 report
is recognised as an on-curve point, compressed to the parity the y-coordinate
dictates, and that anything off-curve or oddly sized is refused rather than
silently truncated to 32 bytes. A fake card then drives `run()` end to end so
the printed lines quoted in the report cannot drift from the code.

Run: python test_hwtest_65byte_pubkey.py
"""

import io
import os
import secrets
import sys

import bip340
import hwtest_65byte_pubkey as hw

# GET_PUBKEY response recorded in section 6.1 of
# docs/HARDWARE_TEST_REPORT_2026-09-01.j3r452.md.
J3R452_PUBKEY_65 = bytes.fromhex(
    "042f3253009b4481805ae7b87e46fcc0b1a469b9e510fd1d9767bf146fb61abec8"
    "987303f74519a22b0c75d9cccee43ae61025d018c28fb5be47a1de35cfdad628"
)


def test_report_key_is_on_curve():
    x = int.from_bytes(J3R452_PUBKEY_65[1:33], "big")
    y = int.from_bytes(J3R452_PUBKEY_65[33:], "big")
    assert hw.point_on_curve(x, y)
    # y ends in 0x28, so the compressed prefix must be 0x02.
    assert y % 2 == 0


def test_normalize_65_byte_key():
    out = hw.normalize_pubkey(J3R452_PUBKEY_65)
    assert len(out) == 33
    assert out[0] == 0x02
    assert out[1:] == J3R452_PUBKEY_65[1:33]
    # The compressed form round-trips through the repo's own BIP-340 helper
    # and lifts to the same point the card sent.
    lifted = bip340.lift_x(int.from_bytes(bip340.x_only(out), "big"))
    assert lifted is not None
    assert lifted[0] == int.from_bytes(J3R452_PUBKEY_65[1:33], "big")


def test_normalize_odd_y_gets_03_prefix():
    x = int.from_bytes(J3R452_PUBKEY_65[1:33], "big")
    y = int.from_bytes(J3R452_PUBKEY_65[33:], "big")
    neg = b"\x04" + x.to_bytes(32, "big") + (bip340.P - y).to_bytes(32, "big")
    assert hw.normalize_pubkey(neg)[0] == 0x03


def test_normalize_33_byte_passthrough():
    compressed = hw.normalize_pubkey(J3R452_PUBKEY_65)
    assert hw.normalize_pubkey(compressed) == compressed


def test_normalize_rejects_off_curve_and_bad_lengths():
    tampered = bytearray(J3R452_PUBKEY_65)
    tampered[-1] ^= 0x01
    for bad in (
        bytes(tampered),                   # y off by one: not on the curve
        J3R452_PUBKEY_65[:64],             # truncated
        b"\x05" + J3R452_PUBKEY_65[1:],    # wrong prefix
        J3R452_PUBKEY_65[1:33],            # bare 32-byte x
        b"\x02" + b"\xff" * 32,            # x >= P
        b"",
    ):
        try:
            hw.normalize_pubkey(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted invalid pubkey {bad.hex()!r}")


class _FakeCard:
    """
    Signs with a host-side BIP-340 signer and returns the pubkey in whichever
    encoding the test asks for, so `run()` can be exercised without silicon.
    """

    def __init__(self, uncompressed: bool):
        self.d = int.from_bytes(secrets.token_bytes(32), "big") % bip340.N or 1
        point = bip340._point_mul(bip340.G, self.d)
        x, y = point
        if uncompressed:
            self.pubkey = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        else:
            self.pubkey = bytes([0x02 if y % 2 == 0 else 0x03]) + x.to_bytes(32, "big")
        # BIP-340 signs with the even-y key; fold the parity in like the applet.
        if y % 2:
            self.d = bip340.N - self.d
        self.pub_x = x.to_bytes(32, "big")

    def get_pubkey(self) -> bytes:
        return self.pubkey

    def sign(self, msg: bytes) -> bytes:
        k = int.from_bytes(secrets.token_bytes(32), "big") % bip340.N or 1
        rx, ry = bip340._point_mul(bip340.G, k)
        if ry % 2:
            k = bip340.N - k
        r = rx.to_bytes(32, "big")
        e = int.from_bytes(bip340.tagged_hash("BIP0340/challenge", r + self.pub_x + msg), "big") % bip340.N
        s = (k + e * self.d) % bip340.N
        return r + s.to_bytes(32, "big")


def test_run_passes_against_65_byte_card():
    out = io.StringIO()
    assert hw.run(_FakeCard(uncompressed=True), rounds=3, out=out)
    text = out.getvalue()
    for line in (
        "Public key point on secp256k1: True",
        "SIGN_ARBITRARY + BIP-340 verify [1/3]: PASS",
        "SIGN_ARBITRARY + BIP-340 verify [3/3]: PASS",
        "Identical-message signature #1 verifies: PASS",
        "Identical-message signature #2 verifies: PASS",
        "Fresh nonce across identical messages: PASS",
        "MANUAL HARDWARE SELFTEST: PASS",
    ):
        assert line in text, f"missing {line!r} in:\n{text}"


REPORTS = (
    "../../docs/HARDWARE_TEST_REPORT_2026-09-01.j3r452.md",
    "../../docs/HARDWARE_TEST_REPORT_2026-09-01.j3r452.zh-CN.md",
)


def _section8_results(path: str) -> list:
    """The lines inside the ```text block under the section-8 'Results' heading."""
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, path), encoding="utf-8") as f:
        text = f.read()
    start = text.index("MANUAL HARDWARE SELFTEST: PASS")
    block_start = text.rindex("```text\n", 0, start) + len("```text\n")
    block_end = text.index("```", block_start)
    return text[block_start:block_end].rstrip("\n").split("\n")


def test_every_run_line_is_quoted_in_both_reports():
    """
    The script's docstring says every line it prints is quoted verbatim in the
    report. Hold it to that: run() against a 65-byte fake card must produce
    exactly the lines of the section-8 results block, in order, with the two
    key-bearing lines pinned to the section-6.1 key and its compressed form.
    """
    out = io.StringIO()
    assert hw.run(_FakeCard(uncompressed=True), rounds=3, out=out)
    emitted = out.getvalue().rstrip("\n").split("\n")

    def shape(line: str) -> str:
        head, _, _ = line.partition(": ")
        return head if head in ("GET_PUBKEY raw (65 bytes)", "Compressed pubkey") else line

    expected_raw = f"GET_PUBKEY raw (65 bytes): {J3R452_PUBKEY_65.hex()}"
    expected_comp = f"Compressed pubkey: {hw.normalize_pubkey(J3R452_PUBKEY_65).hex()}"
    for path in REPORTS:
        quoted = _section8_results(path)
        assert [shape(l) for l in quoted] == [shape(l) for l in emitted], (
            f"{path} section 8 results differ from run() output:\n"
            f"report: {quoted}\nrun():  {emitted}"
        )
        assert expected_raw in quoted, f"{path}: raw key line does not match section 6.1"
        assert expected_comp in quoted, f"{path}: compressed key line does not match section 6.1"


def test_run_passes_against_33_byte_card():
    out = io.StringIO()
    assert hw.run(_FakeCard(uncompressed=False), rounds=1, out=out)
    assert "MANUAL HARDWARE SELFTEST: PASS" in out.getvalue()


def test_run_fails_cleanly_on_garbage_pubkey():
    class Garbage(_FakeCard):
        def get_pubkey(self):
            return b"\x04" + b"\x00" * 64

    out = io.StringIO()
    assert not hw.run(Garbage(uncompressed=True), rounds=1, out=out)
    text = out.getvalue()
    assert "Public key point on secp256k1: False" in text
    assert "MANUAL HARDWARE SELFTEST: FAIL" in text


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"ok  {t.__name__}")
    print("all tests passed")
    sys.exit(0)
