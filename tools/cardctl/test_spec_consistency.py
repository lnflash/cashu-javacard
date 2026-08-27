#!/usr/bin/env python3
"""
Asserts that spec/APDU.md and cardctl.py still agree.

This repo's characteristic bug is not a crash — it is a document and an
implementation drifting apart while both look fine on their own. It has
happened three times:

  * `keyset_id` documented as ASCII bytes, so the driver ASCII-encoded it and
    stored half a NUT-02 id. Every test passed; every loaded proof was
    unspendable.
  * the 32-byte field documented as the "secret", which cannot fit — it is the
    nonce.
  * `SPEND_PROOF`'s message documented as
    `SHA-256(keyset_id || secret || amount || recipient_pubkey)` while NUT-XX
    specified `SHA256(UTF8(Proof.secret))`.

Each one was found by a human reading two files side by side. That does not
scale and it is not reliable. These tests do it on every push.

Deliberately parses the *published* spec rather than importing shared
constants: a shared constant cannot catch a doc that lies, and the doc is what
implementers read. Runs with no card, no reader and no pyscard.
"""
import pathlib
import re
import sys

import cardctl

SPEC_DIR = pathlib.Path(__file__).resolve().parents[2] / "spec"
APDU_MD = SPEC_DIR / "APDU.md"
NUT_XX_MD = SPEC_DIR / "NUT-XX.md"


def _apdu_text() -> str:
    return APDU_MD.read_text(encoding="utf-8")


def test_every_documented_command_matches_its_ins_constant():
    """`### GET_PROOF (0x13)` must equal `INS_GET_PROOF = 0x13`."""
    headings = re.findall(r"^### ([A-Z_]+) \(0x([0-9A-Fa-f]{2})\)", _apdu_text(), re.M)
    assert headings, "no command headings found — did APDU.md's format change?"

    for name, hex_value in headings:
        const = f"INS_{name}"
        assert hasattr(cardctl, const), f"{APDU_MD.name} documents {name} but cardctl has no {const}"
        documented = int(hex_value, 16)
        actual = getattr(cardctl, const)
        assert actual == documented, (
            f"{name}: spec says 0x{documented:02X}, cardctl.{const} is 0x{actual:02X}"
        )


def test_every_ins_constant_is_documented():
    """The other direction: an undocumented command is how a spec goes stale."""
    documented = {n for n, _ in re.findall(r"^### ([A-Z_]+) \(0x([0-9A-Fa-f]{2})\)", _apdu_text(), re.M)}
    implemented = {n[4:] for n in dir(cardctl) if n.startswith("INS_")}
    missing = implemented - documented
    assert not missing, f"cardctl implements undocumented commands: {sorted(missing)}"


def test_documented_cla_matches():
    assert "CLA = `B0`" in _apdu_text() or "`CLA = B0`" in _apdu_text(), \
        "APDU.md no longer states the CLA in the expected form"
    assert cardctl.CLA == 0xB0, f"cardctl.CLA is 0x{cardctl.CLA:02X}, spec says 0xB0"


def _proof_layout() -> dict:
    """Parse the GET_PROOF response table into {offset: (length, description)}."""
    body = _apdu_text().split("### GET_PROOF (0x13)")[1].split("### GET_SLOT_STATUS")[0]
    rows = re.findall(r"^\| (\d+) \| (\d+) \| (.+?) \|$", body, re.M)
    assert rows, "could not parse the GET_PROOF response table"
    return {int(off): (int(ln), desc) for off, ln, desc in rows}


def test_proof_slot_size_matches():
    layout = _proof_layout()
    last = max(layout)
    total = last + layout[last][0]
    assert total == cardctl.PROOF_SIZE, (
        f"spec proof slot totals {total} bytes, cardctl.PROOF_SIZE is {cardctl.PROOF_SIZE}"
    )


def test_proof_field_offsets_and_lengths_match_the_parser():
    """
    The offsets the spec publishes must be the offsets get_proof actually
    slices. A silent disagreement here is the keyset-truncation bug's shape.
    """
    layout = _proof_layout()
    expected = {0: 1, 1: 8, 9: 4, 13: 32, 45: 33}
    assert {off: ln for off, (ln, _) in layout.items()} == expected, (
        f"proof layout changed: {[(o, l) for o, (l, _) in sorted(layout.items())]}"
    )

    # Drive the real parser with a body whose every field is distinguishable,
    # then assert each landed where the spec says it does.
    body = (
        bytes([0x01])
        + bytes.fromhex("0059534ce0bfa19a")
        + (1234).to_bytes(4, "big")
        + bytes(range(32))
        + b"\x02" + bytes(range(1, 33))
    )
    assert len(body) == cardctl.PROOF_SIZE

    class _Conn:
        def transmit(self, apdu):
            return list(body), 0x90, 0x00

    card = cardctl.Card.__new__(cardctl.Card)
    card.connection = _Conn()
    card.verbose = False
    p = card.get_proof(0)

    assert p["keyset_id"] == "0059534ce0bfa19a", p["keyset_id"]
    assert p["amount"] == 1234
    assert p["nonce"] == bytes(range(32))
    assert p["c"] == b"\x02" + bytes(range(1, 33))


def test_keyset_id_is_documented_as_raw_bytes_not_ascii():
    """
    The exact wording that caused the truncation bug. A NUT-02 id is 16 hex
    chars; ASCII-encoded, only half of it fits the 8-byte field.
    """
    _, desc = _proof_layout()[1]
    assert "raw" in desc.lower(), f"keyset row no longer says raw: {desc!r}"
    assert "ascii" not in desc.lower(), (
        f"keyset row describes ASCII encoding again — that stores half an id: {desc!r}"
    )


def test_the_32_byte_field_is_documented_as_the_nonce():
    """A NUT-10 P2PK secret is ~150 bytes of JSON and cannot live in 32."""
    _, desc = _proof_layout()[13]
    assert "nonce" in desc.lower(), f"offset-13 row no longer says nonce: {desc!r}"


def test_spend_proof_message_matches_nut_xx():
    """
    APDU.md once documented a bespoke
    `SHA-256(keyset_id || secret || amount || recipient_pubkey)` while NUT-XX
    specified `SHA256(UTF8(Proof.secret))`. Following the wrong one yields a
    signature the mint rejects.
    """
    apdu = _apdu_text()
    section = apdu.split("### SPEND_PROOF (0x20)")[1].split("### SIGN_ARBITRARY")[0]
    assert "SHA-256(UTF8(Proof.secret))" in section, (
        "SPEND_PROOF message construction no longer matches NUT-XX"
    )
    assert "recipient_pubkey" not in section, (
        "the bespoke recipient_pubkey message construction is back in APDU.md"
    )
    if NUT_XX_MD.exists():
        nut = NUT_XX_MD.read_text(encoding="utf-8")
        assert "SHA256(UTF8(Proof.secret))" in nut or "SHA-256(UTF8(Proof.secret))" in nut, \
            "NUT-XX.md no longer states the canonical SPEND_PROOF message"


def test_load_proof_payload_length_matches_the_documented_fields():
    """Lc must equal the sum of the fields the spec lists for LOAD_PROOF."""
    section = _apdu_text().split("### LOAD_PROOF (0x30)")[1].split("### CLEAR_SPENT")[0]
    lc = re.search(r"\| Lc \| ([0-9A-Fa-f]{2}) \((\d+) bytes\) \|", section)
    assert lc, "could not parse LOAD_PROOF's Lc row"
    assert int(lc.group(1), 16) == int(lc.group(2)), "LOAD_PROOF Lc hex and decimal disagree"

    # The status byte is read-only state, never sent on load.
    layout = _proof_layout()
    sent = sum(ln for off, (ln, _) in layout.items() if off != 0)
    assert int(lc.group(2)) == sent, (
        f"LOAD_PROOF Lc is {lc.group(2)} but the documented fields sum to {sent}"
    )
    assert sent == cardctl.PROOF_SIZE - 1


if __name__ == "__main__":
    import types

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and isinstance(fn, types.FunctionType):
            try:
                fn()
                print(f"PASS  {name}")
            # SystemExit does not inherit from Exception, so it needs naming
            # separately or an exiting test kills the run with no summary.
            except (SystemExit, Exception) as exc:
                failures += 1
                print(f"FAIL  {name}: {exc}")
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
