#!/usr/bin/env python3
"""
Asserts that spec/APDU.md, cardctl.py and CashuApplet.java still agree.

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

Three artefacts have to agree, so all three are read here:

  * spec/APDU.md is *parsed*, never imported from — a shared constant cannot
    catch a doc that lies, and the doc is what implementers read. Both copies
    of the proof layout in it (the GET_PROOF response table and the
    "Proof Slot Layout" block) are parsed and cross-asserted, because a second
    copy nobody checks is just a second place for the same bug to live.
  * cardctl.py is *driven*, not read: the documented header (CLA/INS/P1/P2),
    Lc/Le, response sizes and field order are checked against the bytes the real
    encoder puts on the wire, SELECT included. Summing field lengths would leave
    the field *order* unconstrained, and a misordered load strands money on a
    card permanently. Every documented command is driven — two completeness
    ratchets (`test_every_documented_command_is_driven_through_the_encoder` and
    `test_every_command_with_a_fixed_length_is_length_checked`) fail the day a
    command is added to the doc and to cardctl but not to the case tables,
    because a hand-maintained list of what to check is a list that stops being
    complete.
  * CashuApplet.java's layout constants are scraped with a regex — no JVM
    needed — because the applet is the copy that actually writes EEPROM, and a
    symmetric offset change there would otherwise pass every suite in the repo.

Runs with no card, no reader and no pyscard.
"""
import pathlib
import re
import sys
import traceback

import cardctl
from test_apdu import make_card

SPEC_DIR = pathlib.Path(__file__).resolve().parents[2] / "spec"
APDU_MD = SPEC_DIR / "APDU.md"
NUT_XX_MD = SPEC_DIR / "NUT-XX.md"
APPLET_JAVA = (
    pathlib.Path(__file__).resolve().parents[2]
    / "applet" / "src" / "main" / "java" / "me" / "flashapp" / "cashu" / "CashuApplet.java"
)

# The field names used to compare descriptions written in three different
# houses ("Keyset ID — the NUT-02 id…", "8-byte keyset_id (raw)",
# "PROOF_KEYSET_OFFSET"). Order matters: "Nonce — … from the NUT-10 P2PK
# secret" must resolve as the nonce, and every description is scanned for the
# bare "c" of the C point last so it cannot swallow another field.
_FIELD_KEYWORDS = (
    ("status", r"status"),
    ("keyset_id", r"keyset"),
    ("amount", r"amount"),
    ("nonce", r"nonce"),
    ("c", r"\bc\b"),
)


def _apdu_text() -> str:
    return APDU_MD.read_text(encoding="utf-8")


def _heading_body(pattern: str) -> str:
    """The body of the first `##`/`###` heading matching `pattern`."""
    m = re.search(rf"^#{{2,3}} {pattern}\s*$(.*?)(?=^#{{2,3}} |\Z)", _apdu_text(), re.M | re.S)
    assert m, f"APDU.md has no section whose heading matches /{pattern}/"
    return m.group(1)


def _section(name: str) -> str:
    """
    The body of `### NAME (0xII)`.

    The opcode is matched as a wildcard rather than baked into a split key: with
    the opcode hardcoded, editing a heading to `### GET_PROOF (0x19)` produced
    one useful failure and five cascading `list index out of range`, so a
    maintainer saw six red tests and no cause.
    """
    m = re.search(
        rf"^### {name} \(0x[0-9A-Fa-f]{{2}}\)\s*$(.*?)(?=^#{{2,3}} |\Z)",
        _apdu_text(), re.M | re.S,
    )
    assert m, f"APDU.md has no ### {name} section"
    return m.group(1)


def _hex_spans(text: str) -> list:
    """Every backticked run of hex pairs in `text`, as bytes.

    Used to find AIDs wherever prose puts them, so documenting the fallback AID
    does not have to happen in one exact sentence shape.
    """
    spans = []
    for span in re.findall(r"`([0-9A-Fa-f][0-9A-Fa-f ]*)`", text):
        cleaned = span.replace(" ", "")
        if cleaned and len(cleaned) % 2 == 0:
            spans.append(bytes.fromhex(cleaned))
    return spans


def _command_headings() -> list:
    """Every `### NAME (0xII)` as (name, opcode). SELECT is a `##` heading."""
    headings = re.findall(r"^### ([A-Z_]+) \(0x([0-9A-Fa-f]{2})\)", _apdu_text(), re.M)
    assert headings, "no command headings found — did APDU.md's format change?"
    return headings


def _canonical(description: str, where: str) -> str:
    """Reduce a prose field description to the field it names."""
    text = description.lower()
    for name, pattern in _FIELD_KEYWORDS:
        if re.search(pattern, text):
            return name
    raise AssertionError(f"{where}: cannot tell which field {description!r} describes")


def test_every_documented_command_matches_its_ins_constant():
    """`### GET_PROOF (0x13)` must equal `INS_GET_PROOF = 0x13`."""
    for name, hex_value in _command_headings():
        const = f"INS_{name}"
        assert hasattr(cardctl, const), f"{APDU_MD.name} documents {name} but cardctl has no {const}"
        documented = int(hex_value, 16)
        actual = getattr(cardctl, const)
        assert actual == documented, (
            f"{name}: spec says 0x{documented:02X}, cardctl.{const} is 0x{actual:02X}"
        )


def test_every_ins_constant_is_documented():
    """The other direction: an undocumented command is how a spec goes stale."""
    documented = {n for n, _ in _command_headings()}
    implemented = {n[4:] for n in dir(cardctl) if n.startswith("INS_")}
    missing = implemented - documented
    assert not missing, f"cardctl implements undocumented commands: {sorted(missing)}"


def test_documented_cla_matches():
    """The header sentence must state the CLA the driver actually sends."""
    text = _apdu_text()
    stated = f"CLA = {cardctl.CLA:02X}"
    assert f"`{stated}`" in text or f"CLA = `{cardctl.CLA:02X}`" in text, (
        f"APDU.md no longer states {stated} in the expected form"
    )


def test_select_application_matches_the_apdu_the_driver_sends():
    """
    SELECT is a `##` heading with no opcode, so every other check in this file
    skips it — and it is the one command that has to work before any other can.
    A single wrong AID byte in this table (`…85 01 03`) selects nothing, and the
    driver then reports "The applet is probably not installed on this card",
    pointing the operator at the card instead of at the doc.
    """
    body = _heading_body("SELECT APPLICATION")

    fields = {}
    for field in ("CLA", "INS", "P1", "P2", "Lc"):
        m = re.search(rf"^\| {field} \| ([0-9A-Fa-f]{{2}}) \|$", body, re.M)
        assert m, f"SELECT APPLICATION's table has no parsable {field} row"
        fields[field] = int(m.group(1), 16)

    data = re.search(r"^\| Data \| `([0-9A-Fa-f ]+)` \|$", body, re.M)
    assert data, "SELECT APPLICATION's table has no parsable Data row"
    documented_aid = bytes.fromhex(data.group(1).replace(" ", ""))

    assert documented_aid == cardctl.PACKAGE_AID, (
        f"SELECT's Data row is {documented_aid.hex()}, cardctl.PACKAGE_AID is "
        f"{cardctl.PACKAGE_AID.hex()}"
    )
    assert fields["Lc"] == len(cardctl.PACKAGE_AID), (
        f"SELECT documents Lc {fields['Lc']:02X} for a {len(cardctl.PACKAGE_AID)}-byte AID"
    )

    # The whole documented header, driven through the real selector.
    card = make_card([(b"\x00\x01", 0x9000)])
    card.select()
    documented_apdu = bytes(
        [fields["CLA"], fields["INS"], fields["P1"], fields["P2"], fields["Lc"]]
    ) + documented_aid
    assert card.connection.last == documented_apdu, (
        f"spec's SELECT is {documented_apdu.hex()}, cardctl sends "
        f"{card.connection.last.hex()}"
    )

    # cardctl.select() retries with the 8-byte applet AID when the 7-byte
    # package AID is refused. A reader built from a doc that omits the fallback
    # fails on exactly the cards that decline partial matches.
    assert cardctl.APPLET_AID in _hex_spans(body), (
        f"SELECT APPLICATION does not document the {len(cardctl.APPLET_AID)}-byte fallback AID "
        f"{cardctl.APPLET_AID.hex()} that cardctl.select() actually tries"
    )


def test_every_command_table_repeats_the_right_cla_and_ins():
    """
    Each command's own table is what a reader author copies from. A single
    `| CLA | B1 |` there yields 6E00 from the card, and the header sentence
    above would still be correct.
    """
    for name, hex_value in _command_headings():
        section = _section(name)

        cla = re.search(r"^\| CLA \| ([0-9A-Fa-f]{2}) \|$", section, re.M)
        assert cla, f"{name}'s table has no parsable CLA row"
        assert int(cla.group(1), 16) == cardctl.CLA, (
            f"{name}: table says CLA {cla.group(1)}, cardctl sends {cardctl.CLA:02X}"
        )

        ins = re.search(r"^\| INS \| ([0-9A-Fa-f]{2}) \|$", section, re.M)
        assert ins, f"{name}'s table has no parsable INS row"
        assert int(ins.group(1), 16) == int(hex_value, 16), (
            f"{name}: heading says 0x{hex_value}, its table says {ins.group(1)}"
        )


def _proof_layout() -> dict:
    """Parse the GET_PROOF response table into {offset: (length, description)}."""
    rows = re.findall(r"^\| (\d+) \| (\d+) \| (.+?) \|$", _section("GET_PROOF"), re.M)
    assert rows, "could not parse the GET_PROOF response table"
    return {int(off): (int(ln), desc) for off, ln, desc in rows}


def _proof_slot_layout_block() -> dict:
    """Parse the fenced `## Proof Slot Layout` block into {offset: (length, description)}."""
    body = _heading_body("Proof Slot Layout")
    fence = re.search(r"```\n(.*?)```", body, re.S)
    assert fence, "the Proof Slot Layout section no longer contains a fenced layout block"
    rows = re.findall(r"^(\d+)\s+(\d+)\s+(.+)$", fence.group(1), re.M)
    assert rows, "could not parse the Proof Slot Layout block"
    return {int(off): (int(ln), desc.strip()) for off, ln, desc in rows}


def _assert_field_wording(layout: dict, where: str) -> None:
    """
    The exact wording that caused two of the three historical bugs: a keyset id
    described as ASCII stores half a NUT-02 id, and a 32-byte field described as
    the secret cannot hold a ~150-byte NUT-10 P2PK JSON string.
    """
    _, keyset = layout[1]
    assert "raw" in keyset.lower(), f"{where}: keyset row no longer says raw: {keyset!r}"
    assert "ascii" not in keyset.lower(), (
        f"{where}: keyset row describes ASCII encoding again — that stores half an id: {keyset!r}"
    )
    _, nonce = layout[13]
    assert "nonce" in nonce.lower(), f"{where}: offset-13 row no longer says nonce: {nonce!r}"


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

    p = make_card([(body, 0x9000)]).get_proof(0)

    assert p["keyset_id"] == "0059534ce0bfa19a", p["keyset_id"]
    assert p["amount"] == 1234
    assert p["nonce"] == bytes(range(32))
    assert p["c"] == b"\x02" + bytes(range(1, 33))


def test_both_copies_of_the_proof_layout_in_apdu_md_agree():
    """
    APDU.md publishes the layout twice: the GET_PROOF response table and the
    `## Proof Slot Layout` block. Only the table used to be parsed, so the
    section actually titled for the layout could be rewritten to reintroduce
    the secret-vs-nonce bug verbatim with every test still green.
    """
    table = _proof_layout()
    block = _proof_slot_layout_block()
    assert {off: ln for off, (ln, _) in block.items()} == {off: ln for off, (ln, _) in table.items()}, (
        "the Proof Slot Layout block disagrees with the GET_PROOF response table: "
        f"{sorted((o, l) for o, (l, _) in block.items())} vs "
        f"{sorted((o, l) for o, (l, _) in table.items())}"
    )
    _assert_field_wording(table, "GET_PROOF response table")
    _assert_field_wording(block, "Proof Slot Layout block")


def test_proof_slot_layout_totals_match_the_driver():
    """The EEPROM budget the spec advertises must be slots × slot size."""
    body = _heading_body("Proof Slot Layout")

    size = re.search(r"exactly \*\*(\d+) bytes\*\*", body)
    assert size, "the Proof Slot Layout section no longer states the slot size in bytes"
    assert int(size.group(1)) == cardctl.PROOF_SIZE, (
        f"spec says a slot is {size.group(1)} bytes, cardctl.PROOF_SIZE is {cardctl.PROOF_SIZE}"
    )

    total = re.search(r"(\d+) slots [x×] (\d+) bytes = \*\*([\d,]+) bytes\*\*", body)
    assert total, "the Proof Slot Layout section no longer states the EEPROM total"
    slots, per_slot, advertised = (
        int(total.group(1)), int(total.group(2)), int(total.group(3).replace(",", ""))
    )
    assert slots == cardctl.MAX_PROOFS, (
        f"spec says {slots} slots, cardctl.MAX_PROOFS is {cardctl.MAX_PROOFS}"
    )
    assert per_slot == cardctl.PROOF_SIZE, (
        f"spec's total is computed from {per_slot} bytes per slot, cardctl.PROOF_SIZE is "
        f"{cardctl.PROOF_SIZE}"
    )
    assert advertised == slots * per_slot, (
        f"{slots} × {per_slot} is {slots * per_slot}, but the spec advertises {advertised}"
    )


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
    section = _section("SPEND_PROOF")
    assert "SHA-256(UTF8(Proof.secret))" in section, (
        "SPEND_PROOF message construction no longer matches NUT-XX"
    )
    assert "recipient_pubkey" not in section, (
        "the bespoke recipient_pubkey message construction is back in APDU.md"
    )

    # Unconditional on purpose. NUT-XX is a placeholder name, so the file gets
    # renamed the day the NUT is numbered — and a `if NUT_XX_MD.exists():`
    # guard turned that rename into a silent pass, with APDU.md's link left
    # dangling and the canonical definition unchecked. Failing here is what
    # forces the link to be updated with the file.
    assert NUT_XX_MD.exists(), (
        f"{NUT_XX_MD} is missing — the canonical SPEND_PROOF message has no home. If the NUT "
        "was renumbered, update this path and APDU.md's link to it together."
    )
    nut = NUT_XX_MD.read_text(encoding="utf-8")
    assert "SHA256(UTF8(Proof.secret))" in nut or "SHA-256(UTF8(Proof.secret))" in nut, \
        "NUT-XX.md no longer states the canonical SPEND_PROOF message"
    assert "NUT-XX.md" in _apdu_text(), (
        "APDU.md no longer links to the canonical SPEND_PROOF message definition"
    )


def _length_row(name: str, field: str) -> int:
    """
    Parse `| Le | 4E (78 bytes) |` out of a command table, returning 0x4E.

    Where the row spells the value both ways, the two must agree — the hex is
    what a reader puts on the wire and the decimal is what a human reads.
    """
    m = re.search(
        rf"^\| {field} \| ([0-9A-Fa-f]{{2}})(?: \((\d+) bytes[^)]*\))? \|$",
        _section(name), re.M,
    )
    assert m, f"could not parse {name}'s {field} row"
    if m.group(2) is not None:
        assert int(m.group(1), 16) == int(m.group(2)), (
            f"{name} {field}: hex {m.group(1)} and decimal {m.group(2)} disagree"
        )
    return int(m.group(1), 16)


def _param_row(name: str, field: str) -> str:
    """The raw cell text of a command table's `P1`/`P2` row."""
    m = re.search(rf"^\| {field} \| (.+?) \|$", _section(name), re.M)
    assert m, f"could not parse {name}'s {field} row"
    return m.group(1).strip()


def _param_byte(name: str, field: str) -> int:
    """
    Parse `| P2 | DE (deadbeef confirmation byte) |` out of a command table.

    A trailing parenthetical is prose for the reader; the leading hex pair is
    what goes on the wire.
    """
    value = _param_row(name, field)
    m = re.fullmatch(r"`?([0-9A-Fa-f]{2})`?(?: \(.*\))?", value)
    assert m, f"{name}'s {field} row is not a literal byte: {value!r}"
    return int(m.group(1), 16)


def _wire(method: str, *args, response: bytes = b"") -> tuple:
    """Run a real Card method against a fake reader; return (P1, P2, Lc, Le)."""
    card = make_card([(response, 0x9000)])
    getattr(card, method)(*args)
    apdu = card.connection.last
    assert apdu[:2] == bytes([cardctl.CLA, apdu[1]]) and len(apdu) >= 4, apdu.hex()
    p1, p2 = apdu[2], apdu[3]
    if len(apdu) == 4:
        return p1, p2, None, None
    if len(apdu) == 5:
        return p1, p2, None, apdu[4]
    lc = apdu[4]
    assert len(apdu) >= 5 + lc, f"{method}: Lc {lc} exceeds the APDU it was sent in"
    return p1, p2, lc, apdu[5 + lc] if len(apdu) > 5 + lc else None


_PROOF_BODY = b"\x01" + bytes(8) + bytes(4) + bytes(32) + b"\x02" + bytes(32)

# (command, method, args, canned response). Every command whose table states an
# Lc or Le in the fixed `XX` form.
_LENGTH_CASES = (
    ("GET_INFO", "get_info", (), bytes(8)),
    ("GET_PUBKEY", "get_pubkey", (), bytes(33)),
    ("GET_BALANCE", "get_balance", (), bytes(4)),
    ("GET_PROOF_COUNT", "get_proof_count", (), b"\x00"),
    ("GET_PROOF", "get_proof", (0,), _PROOF_BODY),
    ("GET_SLOT_STATUS", "get_slot_status", (), bytes(32)),
    ("SPEND_PROOF", "spend_proof", (0, bytes(32)), bytes(64)),
    ("SIGN_ARBITRARY", "sign", (bytes(32),), bytes(64)),
    ("LOAD_PROOF", "load_proof", (bytes(8), 1, bytes(32), b"\x02" + bytes(32)), b"\x00"),
    ("CLEAR_SPENT", "clear_spent", (), b"\x00"),
)

# The commands deliberately absent from _LENGTH_CASES, and why — this set is the
# only sanctioned way out of the completeness ratchet below, so the reason has to
# live here rather than in a comment nobody re-reads:
#
#   * VERIFY_PIN / SET_PIN document `Lc | 04–08` and CHANGE_PIN documents
#     `Lc | Variable`, because a PIN is 4–8 bytes. There is no single documented
#     number to compare a sent byte against; test_apdu.py pins those encodings.
#   * LOCK_CARD is a bare 4-byte APDU — it carries no data and expects no
#     response body, so it documents neither Lc nor Le. Its P2 is the
#     confirmation byte, checked in test_lock_card_p2_is_the_confirmation_byte.
_NOT_FIXED_LENGTH = {"VERIFY_PIN", "SET_PIN", "CHANGE_PIN", "LOCK_CARD"}

# Every documented command, driven through the real encoder. The four above are
# absent from _LENGTH_CASES but their headers are still checked, so they are
# added back here.
_WIRE_CASES = _LENGTH_CASES + (
    ("VERIFY_PIN", "verify_pin", (b"1234",), b""),
    ("SET_PIN", "set_pin", (b"1234",), b""),
    ("CHANGE_PIN", "change_pin", (b"1234", b"5678"), b""),
    ("LOCK_CARD", "lock_card", (), b""),
)

# Commands whose P1 carries a caller-chosen slot index rather than a fixed byte.
# These are the two that move money: a P1 documented as a literal `00` sends a
# reader author to slot 0 on every tap, which for SPEND_PROOF is an irreversible
# spend of the wrong proof.
_SLOT_INDEXED = {"GET_PROOF", "SPEND_PROOF"}

# The response body size each command's prose advertises. Tied to the driver's
# constants where the driver has one, so a coordinated doc+encoder edit still has
# to face cardctl's model of the card.
_RESPONSE_SIZES = {
    "GET_INFO": 8,
    "GET_PUBKEY": 33,
    "GET_BALANCE": 4,
    "GET_PROOF_COUNT": 1,
    "GET_PROOF": cardctl.PROOF_SIZE,
    "GET_SLOT_STATUS": cardctl.MAX_PROOFS,
    "SPEND_PROOF": 64,
    "SIGN_ARBITRARY": 64,
    "LOAD_PROOF": 1,
    "CLEAR_SPENT": 1,
}


def test_every_documented_command_is_driven_through_the_encoder():
    """
    The completeness ratchet for _WIRE_CASES. Without it, command #15 arrives
    with a documented section, an INS constant, and not one byte of its header
    ever compared against the wire — and the suite reports success.
    """
    driven = {name for name, _, _, _ in _WIRE_CASES}
    documented = {name for name, _ in _command_headings()}
    assert driven == documented, (
        f"_WIRE_CASES does not drive {sorted(documented - driven)}"
        + (f" and drives undocumented {sorted(driven - documented)}" if driven - documented else "")
    )


def test_every_command_with_a_fixed_length_is_length_checked():
    """
    The completeness ratchet for _LENGTH_CASES. This suite exists because
    GET_PROOF was documented `Le 4D (77 bytes)`; a hand-maintained tuple with no
    ratchet lets that exact bug back in on the next command added, with all
    tests green. `test_every_ins_constant_is_documented` forces the *section* to
    exist; nothing forced it to be length-checked.
    """
    covered = {name for name, _, _, _ in _LENGTH_CASES}
    documented = {name for name, _ in _command_headings()}
    assert not covered & _NOT_FIXED_LENGTH, (
        f"{sorted(covered & _NOT_FIXED_LENGTH)} is both length-checked and excused from being "
        "length-checked — drop it from _NOT_FIXED_LENGTH"
    )
    assert covered | _NOT_FIXED_LENGTH == documented, (
        f"_LENGTH_CASES does not cover {sorted(documented - covered - _NOT_FIXED_LENGTH)}"
    )


def test_every_command_with_a_response_body_is_size_checked():
    """The same ratchet for _RESPONSE_SIZES, which tracks _LENGTH_CASES."""
    assert set(_RESPONSE_SIZES) == {name for name, _, _, _ in _LENGTH_CASES}, (
        "_RESPONSE_SIZES and _LENGTH_CASES have drifted apart: "
        f"{sorted(set(_RESPONSE_SIZES) ^ {name for name, _, _, _ in _LENGTH_CASES})}"
    )


def test_fixed_p1_and_p2_match_the_bytes_cardctl_sends():
    """
    P1 and P2 were never compared against the wire. Rewriting SPEND_PROOF's
    `| P1 |` row to a literal `00` therefore passed: a reader author built from
    that doc irreversibly spends slot 0 on every tap regardless of which proof
    the terminal picked, and the same edit to GET_PROOF makes every read return
    slot 0.
    """
    for name, method, args, response in _WIRE_CASES:
        p1, p2, _, _ = _wire(method, *args, response=response)
        for field, sent in (("P1", p1), ("P2", p2)):
            if name in _SLOT_INDEXED and field == "P1":
                continue  # covered by the slot-index test below
            assert _param_byte(name, field) == sent, (
                f"{name}: spec's {field} is {_param_byte(name, field):02X}, cardctl sends "
                f"{sent:02X}"
            )


def test_slot_indexed_commands_document_and_send_p1_as_the_slot():
    """The two commands that move money must take the slot from the caller."""
    driven = {name for name, _, _, _ in _LENGTH_CASES}
    assert _SLOT_INDEXED <= driven, (
        f"_SLOT_INDEXED names commands that are not driven here: {sorted(_SLOT_INDEXED - driven)}"
    )
    for name, method, args, response in _LENGTH_CASES:
        if name not in _SLOT_INDEXED:
            continue
        documented = _param_row(name, "P1")
        assert "slot" in documented.lower(), (
            f"{name}'s P1 row no longer describes a slot index: {documented!r} — a reader built "
            "from that sends a fixed P1 to every card"
        )
        assert not re.fullmatch(r"`?[0-9A-Fa-f]{2}`?", documented), (
            f"{name}'s P1 is documented as the literal byte {documented!r}, but it carries the "
            "caller's slot index"
        )
        slot = 5
        p1, p2, _, _ = _wire(method, slot, *args[1:], response=response)
        assert p1 == slot, f"{name}: asked for slot {slot}, cardctl put {p1} in P1"
        assert _param_byte(name, "P2") == p2, (
            f"{name}: spec's P2 is {_param_byte(name, 'P2'):02X}, cardctl sends {p2:02X}"
        )


def test_lock_card_p2_is_the_confirmation_byte():
    """
    LOCK_CARD is irreversible and its only guard is the P2 confirmation byte.
    Nothing tied the documented `DE` to cardctl.LOCK_CONFIRM_BYTE, so the two
    could drift and a reader's lock would be rejected — or worse, a doc change
    to a byte the card does not require would suggest the guard is arbitrary.
    """
    assert _param_byte("LOCK_CARD", "P2") == cardctl.LOCK_CONFIRM_BYTE, (
        f"spec's LOCK_CARD P2 is {_param_byte('LOCK_CARD', 'P2'):02X}, "
        f"cardctl.LOCK_CONFIRM_BYTE is {cardctl.LOCK_CONFIRM_BYTE:02X}"
    )
    card = make_card([(b"", 0x9000)])
    card.lock_card()
    assert card.connection.last == bytes([
        cardctl.CLA, cardctl.INS_LOCK_CARD,
        _param_byte("LOCK_CARD", "P1"), cardctl.LOCK_CONFIRM_BYTE,
    ]), card.connection.last.hex()


def _documented_response_sizes(name: str) -> list:
    """
    Every response-body size the section states, in order.

    Two forms carry it: the `| Response |` row's leading `N-byte`/`N bytes`, and
    the `**Response (N bytes):**` header above a field table. Sizes deeper in the
    row are describing sub-fields ("R || s, 32 bytes each") and are handled
    separately.
    """
    section = _section(name)
    sizes = [int(n) for n in re.findall(r"\*\*Response \((\d+) bytes\)", section)]
    row = re.search(r"^\| Response \| (.+?) \|$", section, re.M)
    if row:
        lead = re.match(r"(\d+)[- ]bytes?\b", row.group(1).strip())
        assert lead, (
            f"{name}'s Response row no longer opens with its size in bytes: {row.group(1)!r}"
        )
        sizes.append(int(lead.group(1)))
    return sizes


def test_every_documented_response_size_matches_the_driver():
    """
    Only Lc/Le were checked, so the response prose could say anything. Verified
    by mutation, all green before this test: GET_PUBKEY's `33-byte compressed
    public key` → `32-byte` (a reader reads a truncated key, sets the NUT-11
    P2PK condition to a key nobody holds, and the funds are unspendable);
    GET_SLOT_STATUS's `32 bytes: one status byte per slot` → `16 bytes` (slots
    16–31 invisible, balance looks halved); GET_PROOF's `**Response (78
    bytes):**` → `(77 bytes)`.
    """
    for name, expected in sorted(_RESPONSE_SIZES.items()):
        sizes = _documented_response_sizes(name)
        assert sizes, f"{name} documents no response size at all"
        for size in sizes:
            assert size == expected, (
                f"{name}: spec advertises a {size}-byte response, the driver expects {expected}"
            )

        # `(R || s, 32 bytes each)` — a component size stated after the total has
        # to multiply back out to it.
        each = re.search(
            r"\|\s*Response\s*\|[^|\n]*?\(([^)]*?)(\d+) bytes each\)",
            _section(name),
        )
        if each:
            parts = each.group(1).count(r"\|\|") + 1
            assert parts * int(each.group(2)) == expected, (
                f"{name}: {parts} components of {each.group(2)} bytes is "
                f"{parts * int(each.group(2))}, but the response is {expected} bytes"
            )


def test_documented_le_matches_the_documented_response_size():
    """
    The two halves of every read command's contract. GET_INFO is excluded on
    purpose: it documents `Le 00`, the ISO shorthand for "up to 256 bytes",
    which is not its 8-byte response size.
    """
    for name, expected in sorted(_RESPONSE_SIZES.items()):
        if name == "GET_INFO":
            continue
        assert _length_row(name, "Le") == expected, (
            f"{name}: spec asks for Le {_length_row(name, 'Le'):02X} but advertises a "
            f"{expected}-byte response"
        )


def test_every_documented_length_matches_the_bytes_cardctl_sends():
    """
    Every command's Lc/Le, not just LOAD_PROOF's. Documenting GET_PROOF as
    `Le 4D (77 bytes)` costs the last byte of the C point, and the mint rejects
    the redemption — the failure looks like a bad card, not a bad doc.
    """
    for name, method, args, response in _LENGTH_CASES:
        _, _, sent_lc, sent_le = _wire(method, *args, response=response)
        for field, sent in (("Lc", sent_lc), ("Le", sent_le)):
            documented = re.search(rf"^\| {field} \|", _section(name), re.M)
            assert bool(documented) == (sent is not None), (
                f"{name}: spec {'documents' if documented else 'omits'} {field} but cardctl "
                f"{'sends' if sent is not None else 'omits'} it"
            )
            if sent is not None:
                assert _length_row(name, field) == sent, (
                    f"{name}: spec's {field} is "
                    f"{_length_row(name, field):02X}, cardctl sends {sent:02X}"
                )

    # The two lengths that are also constants, asserted against the constants so
    # a coordinated edit to doc and encoder still has to face the driver's model
    # of the card.
    assert _length_row("GET_PROOF", "Le") == cardctl.PROOF_SIZE
    assert _length_row("GET_SLOT_STATUS", "Le") == cardctl.MAX_PROOFS
    assert _length_row("LOAD_PROOF", "Lc") == cardctl.PROOF_SIZE - 1


def _documented_load_proof_fields() -> list:
    """LOAD_PROOF's Data row as ordered (length, canonical name) pairs."""
    row = re.search(r"^\| Data \| (.+?) \|$", _section("LOAD_PROOF"), re.M)
    assert row, "could not parse LOAD_PROOF's Data row"
    fields = re.findall(r"(\d+)-byte (\w+)", row.group(1))
    assert fields, f"LOAD_PROOF's Data row lists no `N-byte name` fields: {row.group(1)!r}"
    return [(int(n), _canonical(name, "LOAD_PROOF Data row")) for n, name in fields]


def test_load_proof_documents_the_fields_in_the_order_it_sends_them():
    """
    Summing the field lengths leaves the *order* unconstrained: a Data row
    reading `amount + keyset_id + C + nonce` sums to the same 77 bytes. A
    firmware or reader author following that misparses all four fields, and
    every proof loaded through it is unspendable — money stranded on the card
    with no error anywhere.
    """
    layout = _proof_layout()
    # The status byte is read-only state, never sent on load.
    expected = [
        (ln, _canonical(desc, "GET_PROOF response table"))
        for off, (ln, desc) in sorted(layout.items()) if off != 0
    ]
    assert _documented_load_proof_fields() == expected, (
        f"LOAD_PROOF's Data row is {_documented_load_proof_fields()} but the proof layout is "
        f"{expected}"
    )


def test_load_proof_sends_each_field_where_the_spec_says_it_goes():
    """The documented order, driven through the real encoder byte for byte."""
    keyset = b"\x01" * 8
    amount = 1234
    nonce = bytes(range(32))
    c = b"\x02" + bytes(range(1, 33))
    values = {
        "keyset_id": keyset,
        "amount": amount.to_bytes(4, "big"),
        "nonce": nonce,
        "c": c,
    }

    card = make_card([(b"\x07", 0x9000)])
    assert card.load_proof(keyset, amount, nonce, c) == 7
    sent = card.connection.last
    payload = sent[5:5 + sent[4]]

    offset = 0
    for length, name in _documented_load_proof_fields():
        assert payload[offset:offset + length] == values[name], (
            f"spec puts {name} at offset {offset} of LOAD_PROOF's payload; cardctl sends "
            f"{payload[offset:offset + length].hex()} there"
        )
        offset += length
    assert offset == len(payload), (
        f"the documented fields cover {offset} of {len(payload)} sent bytes"
    )
    assert offset == cardctl.PROOF_SIZE - 1


def _applet_constants() -> dict:
    """
    Scrape CashuApplet.java's layout constants. A regex, not a JVM: this suite
    has to run in the Python job, and the applet is the copy that writes EEPROM.
    """
    src = APPLET_JAVA.read_text(encoding="utf-8")
    consts = {
        n: int(v) for n, v in
        re.findall(r"static final short (PROOF_\w+|MAX_PROOFS)\s*=\s*\(short\)\s*(\d+)", src)
    }
    assert consts, f"could not scrape layout constants from {APPLET_JAVA.name}"
    return consts


def test_applet_layout_constants_match_the_spec_and_the_driver():
    """
    The applet is the third party to this contract, and nothing else checks it:
    CashuAppletTest round-trips bytes 1..77 as an opaque blob, so a *symmetric*
    offset change inside the applet passes the Java suite, passes cardctl, and
    would pass every other test here — on the firmware holding bearer money.
    """
    consts = _applet_constants()
    layout = _proof_layout()

    assert "PROOF_SECRET_OFFSET" not in APPLET_JAVA.read_text(encoding="utf-8"), (
        "the 32-byte field is the nonce, not the secret — a NUT-10 P2PK secret is ~150 bytes of "
        "JSON. Rename PROOF_SECRET_OFFSET to PROOF_NONCE_OFFSET."
    )

    assert consts.get("PROOF_SIZE") == cardctl.PROOF_SIZE, (
        f"applet PROOF_SIZE is {consts.get('PROOF_SIZE')}, cardctl.PROOF_SIZE is "
        f"{cardctl.PROOF_SIZE}"
    )
    assert consts.get("PROOF_DATA_LEN") == cardctl.PROOF_SIZE - 1, (
        f"applet PROOF_DATA_LEN is {consts.get('PROOF_DATA_LEN')}, but a load carries "
        f"{cardctl.PROOF_SIZE - 1} bytes"
    )
    assert consts.get("MAX_PROOFS") == cardctl.MAX_PROOFS, (
        f"applet MAX_PROOFS is {consts.get('MAX_PROOFS')}, cardctl.MAX_PROOFS is "
        f"{cardctl.MAX_PROOFS}"
    )

    java_name = {
        "status": "PROOF_STATUS_OFFSET",
        "keyset_id": "PROOF_KEYSET_OFFSET",
        "amount": "PROOF_AMOUNT_OFFSET",
        "nonce": "PROOF_NONCE_OFFSET",
        "c": "PROOF_C_OFFSET",
    }
    for offset, (_, desc) in sorted(layout.items()):
        const = java_name[_canonical(desc, "GET_PROOF response table")]
        assert const in consts, f"{APPLET_JAVA.name} has no {const}"
        assert consts[const] == offset, (
            f"spec puts {const[6:-7].lower()} at offset {offset}, applet {const} is "
            f"{consts[const]}"
        )


if __name__ == "__main__":
    import types

    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and isinstance(fn, types.FunctionType):
            try:
                fn()
                print(f"PASS  {name}")
            # Matches test_apdu.py's runner deliberately: cardctl reports
            # operator errors by raising SystemExit (which derives from
            # BaseException, so it needs naming separately or an exiting test
            # kills the run with no summary), and a parser/command mismatch
            # surfaces as AttributeError. Printing the type and a traceback for
            # non-assertion failures is what turns "list index out of range"
            # into a line number.
            except (SystemExit, Exception) as exc:
                failures += 1
                print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
                if not isinstance(exc, (AssertionError, SystemExit)):
                    traceback.print_exc()
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
