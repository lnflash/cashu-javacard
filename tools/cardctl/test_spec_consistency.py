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
  * cardctl.py is *driven*, not read: the documented Lc/Le and field order are
    checked against the bytes the real encoder puts on the wire. Summing field
    lengths would leave the field *order* unconstrained, and a misordered load
    strands money on a card permanently.
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


def _wire(method: str, *args, response: bytes = b"") -> tuple:
    """Run a real Card method against a fake reader; return its (Lc, Le)."""
    card = make_card([(response, 0x9000)])
    getattr(card, method)(*args)
    apdu = card.connection.last
    assert apdu[:2] == bytes([cardctl.CLA, apdu[1]]) and len(apdu) >= 4, apdu.hex()
    if len(apdu) == 4:
        return None, None
    if len(apdu) == 5:
        return None, apdu[4]
    lc = apdu[4]
    assert len(apdu) >= 5 + lc, f"{method}: Lc {lc} exceeds the APDU it was sent in"
    return lc, apdu[5 + lc] if len(apdu) > 5 + lc else None


_PROOF_BODY = b"\x01" + bytes(8) + bytes(4) + bytes(32) + b"\x02" + bytes(32)

# (command, method, args, canned response). Every command whose table states an
# Lc or Le in the fixed `XX` form; the PIN commands document ranges (`04–08`)
# and are covered by test_apdu.py's encoding tests instead.
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


def test_every_documented_length_matches_the_bytes_cardctl_sends():
    """
    Every command's Lc/Le, not just LOAD_PROOF's. Documenting GET_PROOF as
    `Le 4D (77 bytes)` costs the last byte of the C point, and the mint rejects
    the redemption — the failure looks like a bad card, not a bad doc.
    """
    for name, method, args, response in _LENGTH_CASES:
        sent_lc, sent_le = _wire(method, *args, response=response)
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
