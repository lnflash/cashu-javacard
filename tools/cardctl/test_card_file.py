#!/usr/bin/env python3
"""
Card file interchange — the Python half.

The contract is published in `spec/CARD-FILE.md`, next to APDU.md, and this
suite asserts both halves of this driver against it: the field names
`_slot_from_json` requires and the field names `cmd_dump` emits must be exactly
the names the spec tables list. That is the check a rename fails — parsed from
the published document, the same way test_spec_consistency.py parses APDU.md,
because a shared constant cannot catch a doc that lies and the doc is what the
other implementation is written from.

`testdata/card-file-v1.json` backs that up with bytes cashu-client's
`serializeCardFile` actually wrote, so the Python parser is also checked against
a real artifact rather than only against prose. A fixture proves one file parsed
once; the spec is the contract.

Runs with no card, no reader and no pyscard.
"""
import copy
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import types

import cardctl

HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE / "testdata" / "card-file-v1.json"
SPEC = HERE.parents[1] / "spec" / "CARD-FILE.md"

CARD_PUBKEY = "032994631ef9a4ba5b0db2f44b4d0d8a4b0eec49bed16091c23c171a8c553a03da"
OTHER_PUBKEY = "02" + "11" * 32
C_POINT = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"


def _slot(**over) -> dict:
    base = {
        "keysetId": "0059534ce0bfa19a",
        "amount": 8,
        "nonce": "ab" * 32,
        "C": C_POINT,
        "spent": False,
    }
    base.update(over)
    return base


def _doc(**over) -> dict:
    base = {
        "version": 1,
        "mint": "https://forge.flashapp.me",
        "unit": "sat",
        "cardPubkey": CARD_PUBKEY,
        "slots": [_slot()],
    }
    base.update(over)
    return base


def _write(doc) -> str:
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(doc, fh)
    fh.close()
    return fh.name


def _expect_exit(path_or_doc, needle: str):
    path = path_or_doc if isinstance(path_or_doc, str) else _write(path_or_doc)
    try:
        cardctl.read_card_file(path)
    except SystemExit as exc:
        assert needle in str(exc), f"expected {needle!r} in {str(exc)!r}"
    else:
        raise AssertionError(f"expected SystemExit containing {needle!r}")
    finally:
        if not isinstance(path_or_doc, str):
            os.unlink(path)


# ── the published contract ───────────────────────────────────────────────────
#
# spec/CARD-FILE.md is the thing both implementations are written from, so it is
# the thing to assert against. Parsed, not imported: a shared constant agrees
# with itself no matter what the document says.

def _spec_fields(section: str) -> dict:
    """{field: (type, required)} from the named table in spec/CARD-FILE.md."""
    assert SPEC.exists(), f"missing {SPEC} — the card file schema must be published"
    body = SPEC.read_text(encoding="utf-8").split(f"\n## {section}\n")[1].split("\n## ")[0]
    rows = re.findall(r"^\| `([A-Za-z]+)` \| (\w+) \| (\w+) \|", body, re.M)
    assert rows, f"could not parse the '{section}' table in {SPEC.name}"
    return {name: (typ, req) for name, typ, req in rows}


def test_spec_publishes_every_document_field_the_parser_requires():
    """Drop a field the spec calls required; the parser must name it and refuse."""
    fields = _spec_fields("Document")
    assert set(fields) == {"version", "mint", "unit", "cardPubkey", "slots"}, fields
    for name, (_, required) in fields.items():
        assert required == "yes", f"{name} is optional in the spec but not in the parser"
        d = _doc()
        del d[name]
        _expect_exit(d, name)


def test_spec_publishes_every_slot_field_the_parser_requires():
    fields = _spec_fields("Slot")
    assert set(fields) == {"keysetId", "amount", "nonce", "C", "spent"}, fields
    for name, (_, required) in fields.items():
        assert required == "yes", f"{name} is optional in the spec but not in the parser"
        d = _doc()
        del d["slots"][0][name]
        _expect_exit(d, name)


def test_dump_emits_exactly_the_slot_fields_the_spec_publishes():
    """The writer half. A rename in cmd_dump fails here, not at a card reader."""
    assert set(_dump()["slots"][0]) == set(_spec_fields("Slot"))


def test_fixture_matches_the_published_schema():
    """The fixture is a real cashu-client artifact; it must satisfy the spec too."""
    raw = json.loads(FIXTURE.read_text())
    assert set(raw) >= set(_spec_fields("Document"))
    assert set(raw["slots"][0]) == set(_spec_fields("Slot"))


# ── the cross-toolchain check ────────────────────────────────────────────────

def test_reads_a_file_written_by_cashu_client():
    """The fixture was produced by serializeCardFile, not by hand."""
    assert FIXTURE.exists(), f"missing fixture {FIXTURE}"
    doc = cardctl.read_card_file(str(FIXTURE))

    assert doc["mint"] == "https://forge.flashapp.me"
    assert doc["unit"] == "sat"
    assert cardctl._hex(doc["card_pubkey"]) == CARD_PUBKEY
    assert [s["amount"] for s in doc["slots"]] == [8, 16]
    assert [s["spent"] for s in doc["slots"]] == [False, True]
    # Keyset ids survive as 8 RAW bytes — the ASCII bug's blast radius.
    assert doc["slots"][0]["keyset"] == bytes.fromhex("0059534ce0bfa19a")
    assert len(doc["slots"][0]["nonce"]) == 32
    assert len(doc["slots"][0]["c"]) == 33


def test_fixture_field_names_match_the_schema():
    """A rename on either side must fail loudly here, not at a card."""
    raw = json.loads(FIXTURE.read_text())
    assert set(raw) >= {"version", "mint", "unit", "cardPubkey", "slots"}
    assert set(raw["slots"][0]) == {"keysetId", "amount", "nonce", "C", "spent"}
    # `secret` is the field name that cannot exist: a P2PK secret is ~150 bytes.
    assert "secret" not in raw["slots"][0]


# ── happy path ───────────────────────────────────────────────────────────────

def test_accepts_an_empty_card():
    doc = cardctl.read_card_file(_write(_doc(slots=[])))
    assert doc["slots"] == []


def test_normalises_hex_case():
    d = _doc()
    d["cardPubkey"] = CARD_PUBKEY.upper()
    d["slots"][0]["keysetId"] = "0059534CE0BFA19A"
    doc = cardctl.read_card_file(_write(d))
    assert doc["slots"][0]["keyset"] == bytes.fromhex("0059534ce0bfa19a")


# ── rejections ───────────────────────────────────────────────────────────────

def test_rejects_a_missing_file():
    _expect_exit("/nonexistent/card-file.json", "no such card file")


def test_rejects_invalid_json():
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    fh.write("{ not json")
    fh.close()
    _expect_exit(fh.name, "not valid JSON")
    os.unlink(fh.name)


def test_rejects_a_non_object_document():
    _expect_exit([1, 2, 3], "must be a JSON object")


def test_rejects_an_unknown_version():
    _expect_exit(_doc(version=2), "unsupported card file version")
    _expect_exit(_doc(version=None), "unsupported card file version")


def test_rejects_missing_mint_or_unit():
    _expect_exit(_doc(mint=""), "mint must be a non-empty string")
    _expect_exit(_doc(unit=None), "unit must be a non-empty string")


def test_rejects_a_bad_card_pubkey():
    _expect_exit(_doc(cardPubkey="04" + "ab" * 32), "compressed secp256k1 point")
    _expect_exit(_doc(cardPubkey="02ab"), "cardPubkey")


def test_rejects_slots_that_are_not_a_list():
    _expect_exit(_doc(slots={}), "slots must be an array")


def test_rejects_a_bad_c_point():
    """
    Same guard cardPubkey gets. An uncompressed-looking C is 33 bytes long and
    passes the length check, and is an unspendable proof.
    """
    d = _doc()
    d["slots"][0]["C"] = "04" + "ab" * 32
    _expect_exit(d, "compressed secp256k1 point")
    d["slots"][0]["C"] = "00" + "ab" * 32
    _expect_exit(d, "got 0x00")


def test_rejects_a_half_length_keyset_id():
    """The ASCII-truncation shape: 8 hex chars is half a NUT-02 id."""
    d = _doc()
    d["slots"][0]["keysetId"] = "0059534c"
    _expect_exit(d, "16")


def test_keyset_error_names_the_file_field_not_a_cli_flag():
    """
    There is no --keyset flag on load-file. Pointing at one sends the operator
    hunting through their shell history instead of the JSON field they must fix.
    """
    d = _doc()
    d["slots"][0]["keysetId"] = "0059534c"
    _expect_exit(d, "keysetId")

    try:
        cardctl.read_card_file(_write(d))
    except SystemExit as exc:
        assert "--keyset" not in str(exc), str(exc)

    # The flag still names itself when it really is the flag.
    try:
        cardctl.parse_keyset_id("0059534c")
    except SystemExit as exc:
        assert "--keyset" in str(exc), str(exc)


def test_rejects_an_amount_the_cards_four_byte_field_cannot_hold():
    """
    Caught here or not at all: Card.load_proof does amount.to_bytes(4, "big"),
    which raises a bare OverflowError mid-file, after earlier proofs are already
    committed and cannot be rolled back.
    """
    for bad in (2 ** 32, 2 ** 32 + 1, 2 ** 64):
        d = _doc()
        d["slots"][0]["amount"] = bad
        _expect_exit(d, "amount must be a positive integer")
    # The largest value the field does hold is still accepted.
    d = _doc()
    d["slots"][0]["amount"] = 2 ** 32 - 1
    assert cardctl.read_card_file(_write(d))["slots"][0]["amount"] == 2 ** 32 - 1


def test_requires_the_spent_bit_and_will_not_default_it():
    """
    A missing `spent` is not "unspent", it is unknown — and guessing wrong
    resurrects burned money as spendable balance on the next load.
    """
    for bad in (None, "false", 0, 1):
        d = _doc()
        d["slots"][0]["spent"] = bad
        _expect_exit(d, "spent must be a boolean")
    d = _doc()
    del d["slots"][0]["spent"]
    _expect_exit(d, "spent must be a boolean")


def test_names_the_mistake_when_a_slot_says_secret():
    d = _doc()
    slot = d["slots"][0]
    slot["secret"] = slot.pop("nonce")
    _expect_exit(d, 'has "secret" but no "nonce"')


def test_rejects_a_bad_amount():
    for bad in (0, -1, "8", None, True):
        d = _doc()
        d["slots"][0]["amount"] = bad
        _expect_exit(d, "amount must be a positive integer")


def test_rejects_a_short_nonce():
    d = _doc()
    d["slots"][0]["nonce"] = "ab" * 16
    _expect_exit(d, "nonce")


def test_reports_which_slot_failed():
    d = _doc()
    d["slots"] = [copy.deepcopy(d["slots"][0]), copy.deepcopy(d["slots"][0])]
    d["slots"][1]["nonce"] = "ab"
    _expect_exit(d, "slot 1")


def test_rejects_a_non_object_slot():
    _expect_exit(_doc(slots=["nope"]), "slot 0: expected an object")


# ── dump writes what read accepts ────────────────────────────────────────────

class _DumpCard:
    """Enough of Card for cmd_dump: two slots, one unspent, one spent."""

    def __init__(self):
        self._slots = [
            {"keyset_id": "0059534ce0bfa19a", "amount": 8, "nonce": bytes(range(32)),
             "c": bytes.fromhex(C_POINT), "status": "unspent"},
            {"keyset_id": "008288762774ace1", "amount": 16, "nonce": bytes(range(32)),
             "c": bytes.fromhex(C_POINT), "status": "spent"},
        ]

    def get_pubkey(self):
        return bytes.fromhex(CARD_PUBKEY)

    def get_slot_status(self):
        return bytes([0x01, 0x02] + [0x00] * 30)

    def get_proof(self, index):
        return self._slots[index]


def _run_dump(extra=()) -> str:
    """Run cmd_dump against the fake card. Returns everything it printed."""
    real = cardctl.connect
    cardctl.connect = lambda a: _DumpCard()
    out = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = out
    try:
        args = cardctl.build_parser().parse_args(
            ["dump", "--mint", "https://forge.flashapp.me", *extra]
        )
        assert args.func(args) == 0
    finally:
        sys.stdout = real_stdout
        cardctl.connect = real
    return out.getvalue()


def _dump(out=None, **kwargs) -> dict:
    """
    The document dump produced — read back from stdout, or from `out` when a
    path is given. `--out` is the branch operators actually use, so it is
    exercised through the same assertions rather than assumed to match.
    """
    extra = list(kwargs.get("extra", []))
    if out is not None:
        extra += ["--out", str(out)]
    printed = _run_dump(extra)
    if out is None:
        return json.loads(printed)
    return json.loads(pathlib.Path(out).read_text(encoding="utf-8"))


def test_dump_emits_a_file_this_module_can_read_back():
    """Round trip: what dump writes, read_card_file must accept."""
    doc = _dump()
    assert doc["version"] == cardctl.CARD_FILE_VERSION
    assert doc["cardPubkey"] == CARD_PUBKEY
    assert [s["amount"] for s in doc["slots"]] == [8, 16]

    parsed = cardctl.read_card_file(_write(doc))
    assert [s["amount"] for s in parsed["slots"]] == [8, 16]


def test_dump_uses_the_schema_field_names():
    assert set(_dump()["slots"][0]) == {"keysetId", "amount", "nonce", "C", "spent"}


def test_dump_writes_full_16_char_keyset_ids():
    for slot in _dump()["slots"]:
        assert len(slot["keysetId"]) == 16, slot["keysetId"]


def test_dump_includes_spent_slots_by_default():
    """A spent slot is still owed until it settles — dropping it loses money."""
    assert len(_dump()["slots"]) == 2


def test_dump_unspent_only_skips_spent_slots():
    assert len(_dump(extra=["--unspent-only"])["slots"]) == 1


def test_dump_carries_the_spent_bit_per_slot():
    """
    Without this the file preserves the money and destroys the state needed to
    act on it: the mint side gets N indistinguishable proofs, and a reload turns
    the settled ones back into spendable balance.
    """
    slots = _dump()["slots"]
    assert [s["spent"] for s in slots] == [False, True]
    assert cardctl.read_card_file(_write(_dump()))["slots"][1]["spent"] is True


# ── dump --out ───────────────────────────────────────────────────────────────

def test_dump_out_writes_a_file_that_reads_back():
    """The branch operators actually use. Previously never executed by a test."""
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "card1.json"
        doc = _dump(out=path)

        assert path.exists()
        assert path.read_text(encoding="utf-8").endswith("\n"), "no trailing newline"
        assert doc == _dump(), "--out and stdout disagree"

        parsed = cardctl.read_card_file(str(path))
        assert [s["amount"] for s in parsed["slots"]] == [8, 16]
        assert [s["spent"] for s in parsed["slots"]] == [False, True]


def test_dump_out_refuses_to_clobber_an_existing_file():
    """A card file is often the only off-card record of a card's proofs."""
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "card1.json"
        path.write_text("someone else's proofs", encoding="utf-8")
        try:
            _dump(out=path)
        except SystemExit as exc:
            assert "already exists" in str(exc), str(exc)
        else:
            raise AssertionError("dump --out overwrote an existing file")
        assert path.read_text(encoding="utf-8") == "someone else's proofs"


def test_dump_out_force_overwrites():
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "card1.json"
        path.write_text("stale", encoding="utf-8")
        doc = _dump(out=path, extra=["--force"])
        assert doc["cardPubkey"] == CARD_PUBKEY


# ── load-file ────────────────────────────────────────────────────────────────

class _LoadCard:
    """
    Enough of Card for cmd_load_file. Records every call and writes nothing.

    `occupied` seeds slots already on the card, in slot order, so the
    re-run-after-a-crash path can be driven.
    """

    MAX_SLOTS = 32

    def __init__(self, pubkey: str = CARD_PUBKEY, occupied=()):
        self._pubkey = bytes.fromhex(pubkey)
        self._occupied = [
            {"keyset_id": "0059534ce0bfa19a", "amount": 8, "nonce": n,
             "c": bytes.fromhex(C_POINT), "status": "unspent"}
            for n in occupied
        ]
        self.loaded = []
        self.calls = []

    def get_pubkey(self):
        self.calls.append("get_pubkey")
        return self._pubkey

    def get_info(self):
        self.calls.append("get_info")
        free = self.MAX_SLOTS - len(self._occupied) - len(self.loaded)
        return {"max_slots": self.MAX_SLOTS, "empty": free, "unspent": 0, "spent": 0}

    def get_slot_status(self):
        self.calls.append("get_slot_status")
        n = len(self._occupied)
        return bytes([0x01] * n + [0x00] * (self.MAX_SLOTS - n))

    def get_proof(self, index):
        self.calls.append(f"get_proof {index}")
        return self._occupied[index]

    def verify_pin(self, pin):
        self.calls.append("verify_pin")

    def load_proof(self, keyset_id, amount, nonce, c):
        self.calls.append("load_proof")
        index = len(self._occupied) + len(self.loaded)
        if index >= self.MAX_SLOTS:
            raise AssertionError("load_proof called with no free slot — pre-flight failed")
        self.loaded.append((keyset_id, amount, nonce, c))
        return index


class _FullCard(_LoadCard):
    """A card with exactly one free slot."""

    MAX_SLOTS = 1


def _load_file(doc, card=None, extra=()):
    """Run cmd_load_file against a fake card. Returns (card, printed output)."""
    card = card or _LoadCard()
    path = _write(doc)
    real = cardctl.connect
    cardctl.connect = lambda a: card
    out = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = out
    try:
        args = cardctl.build_parser().parse_args(["load-file", path, *extra])
        assert args.func(args) == 0
    finally:
        sys.stdout = real_stdout
        cardctl.connect = real
        os.unlink(path)
    return card, out.getvalue()


def _expect_load_exit(doc, needle: str, card=None, extra=()):
    """Returns (card, message) so a caller can assert on both."""
    card = card or _LoadCard()
    try:
        _load_file(doc, card=card, extra=extra)
    except SystemExit as exc:
        assert needle in str(exc), f"expected {needle!r} in {str(exc)!r}"
        return card, str(exc)
    raise AssertionError(f"expected SystemExit containing {needle!r}")


def test_load_file_refuses_a_card_the_proofs_are_not_locked_to():
    """
    The headline safety property: these proofs are P2PK-locked to one card, so
    writing them to another mints money nothing can ever spend.
    """
    card, _ = _expect_load_exit(_doc(), "locked to a different card",
                                card=_LoadCard(pubkey=OTHER_PUBKEY))
    assert card.loaded == [], "wrote proofs to the wrong card"
    assert "load_proof" not in card.calls


def test_load_file_checks_the_pubkey_before_touching_the_pin():
    """
    Order matters: a PIN verify against the wrong card burns a retry (three of
    them blocks it) for a load that was never going to be legitimate.
    """
    card, _ = _expect_load_exit(_doc(), "locked to a different card",
                                card=_LoadCard(pubkey=OTHER_PUBKEY),
                                extra=["--pin", "1234"])
    assert "verify_pin" not in card.calls, card.calls


def test_load_file_sends_every_proof_in_file_order():
    d = _doc(slots=[
        _slot(amount=8, nonce="ab" * 32),
        _slot(amount=16, nonce="cd" * 32, keysetId="008288762774ace1"),
    ])
    card, printed = _load_file(d)

    assert card.loaded == [
        (bytes.fromhex("0059534ce0bfa19a"), 8, bytes.fromhex("ab" * 32),
         bytes.fromhex(C_POINT)),
        (bytes.fromhex("008288762774ace1"), 16, bytes.fromhex("cd" * 32),
         bytes.fromhex(C_POINT)),
    ]
    assert "loaded 2 proof(s), 24 sat total" in printed


def test_load_file_verifies_the_pin_before_writing():
    card, _ = _load_file(_doc(), extra=["--pin", "1234"])
    assert card.calls.index("verify_pin") < card.calls.index("load_proof")


def test_load_file_refuses_a_file_larger_than_the_free_slots():
    """
    Checked before the first write, because there is no rollback after it: a
    file that runs the card out of slots mid-way otherwise commits half of
    itself and then dies on 6A84.
    """
    d = _doc(slots=[_slot(nonce="ab" * 32), _slot(nonce="cd" * 32)])
    card, message = _expect_load_exit(d, "needs 2 free slot(s)", card=_FullCard())
    assert card.loaded == [], "wrote proofs before discovering it could not finish"
    assert "this card has 1" in message, message
    assert "Nothing was written" in message, message


def test_load_file_is_idempotent_after_a_partial_load():
    """
    The crash-recovery path. Without the nonce check, the obvious retry writes
    the already-loaded proofs a second time: duplicate proofs, inflated on-card
    balance, and half of them rejected at the mint.
    """
    d = _doc(slots=[_slot(nonce="ab" * 32), _slot(amount=16, nonce="cd" * 32)])
    # First proof already landed before the crash.
    card = _LoadCard(occupied=[bytes.fromhex("ab" * 32)])
    card, printed = _load_file(d, card=card)

    assert [amount for _, amount, _, _ in card.loaded] == [16]
    assert "already loaded, skipping" in printed
    assert "loaded 1 proof(s), 16 sat total" in printed
    assert "1 already on the card" in printed


def test_load_file_does_not_resurrect_spent_proofs():
    """
    LOAD_PROOF has no spent bit. Writing a spent proof back returns it as
    unspent — balance the holder cannot actually move.
    """
    d = _doc(slots=[_slot(nonce="ab" * 32, spent=True),
                    _slot(amount=16, nonce="cd" * 32)])
    card, printed = _load_file(d)

    assert [amount for _, amount, _, _ in card.loaded] == [16]
    assert "1 spent slot(s) not loaded" in printed


def test_load_file_rejects_an_oversized_amount_before_any_write():
    """The OverflowError case, caught at parse time rather than mid-file."""
    d = _doc(slots=[_slot(nonce="ab" * 32), _slot(nonce="cd" * 32, amount=2 ** 32)])
    card, _ = _expect_load_exit(d, "amount must be a positive integer")
    assert card.loaded == []
    assert card.calls == [], "connected to a card before the file was valid"


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and isinstance(fn, types.FunctionType):
            try:
                fn()
                print(f"PASS  {name}")
            except (SystemExit, Exception) as exc:
                failures += 1
                print(f"FAIL  {name}: {exc}")
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
