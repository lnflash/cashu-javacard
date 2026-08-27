#!/usr/bin/env python3
"""
Card file interchange — the Python half.

The schema is defined once, in cashu-client's `src/cardFile.ts`. This suite
proves this driver agrees with it, including against a fixture the TypeScript
side actually wrote (`testdata/card-file-v1.json` — produced by
`serializeCardFile`, not hand-authored, so it cannot drift into agreement with a
wrong Python parser).

Runs with no card, no reader and no pyscard.
"""
import copy
import io
import json
import os
import pathlib
import sys
import tempfile
import types

import cardctl

HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE / "testdata" / "card-file-v1.json"

CARD_PUBKEY = "032994631ef9a4ba5b0db2f44b4d0d8a4b0eec49bed16091c23c171a8c553a03da"
C_POINT = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"


def _doc(**over) -> dict:
    base = {
        "version": 1,
        "mint": "https://forge.flashapp.me",
        "unit": "sat",
        "cardPubkey": CARD_PUBKEY,
        "slots": [
            {
                "keysetId": "0059534ce0bfa19a",
                "amount": 8,
                "nonce": "ab" * 32,
                "C": C_POINT,
            }
        ],
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


# ── the cross-toolchain check ────────────────────────────────────────────────

def test_reads_a_file_written_by_cashu_client():
    """The fixture was produced by serializeCardFile, not by hand."""
    assert FIXTURE.exists(), f"missing fixture {FIXTURE}"
    doc = cardctl.read_card_file(str(FIXTURE))

    assert doc["mint"] == "https://forge.flashapp.me"
    assert doc["unit"] == "sat"
    assert cardctl._hex(doc["card_pubkey"]) == CARD_PUBKEY
    assert [s["amount"] for s in doc["slots"]] == [8, 16]
    # Keyset ids survive as 8 RAW bytes — the ASCII bug's blast radius.
    assert doc["slots"][0]["keyset"] == bytes.fromhex("0059534ce0bfa19a")
    assert len(doc["slots"][0]["nonce"]) == 32
    assert len(doc["slots"][0]["c"]) == 33


def test_fixture_field_names_match_the_schema():
    """A rename on either side must fail loudly here, not at a card."""
    raw = json.loads(FIXTURE.read_text())
    assert set(raw) >= {"version", "mint", "unit", "cardPubkey", "slots"}
    assert set(raw["slots"][0]) == {"keysetId", "amount", "nonce", "C"}
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


def test_rejects_a_half_length_keyset_id():
    """The ASCII-truncation shape: 8 hex chars is half a NUT-02 id."""
    d = _doc()
    d["slots"][0]["keysetId"] = "0059534c"
    _expect_exit(d, "16")


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


def _dump(**kwargs) -> dict:
    real = cardctl.connect
    cardctl.connect = lambda a: _DumpCard()
    out = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = out
    try:
        args = cardctl.build_parser().parse_args(
            ["dump", "--mint", "https://forge.flashapp.me", *kwargs.get("extra", [])]
        )
        assert args.func(args) == 0
    finally:
        sys.stdout = real_stdout
        cardctl.connect = real
    return json.loads(out.getvalue())


def test_dump_emits_a_file_this_module_can_read_back():
    """Round trip: what dump writes, read_card_file must accept."""
    doc = _dump()
    assert doc["version"] == cardctl.CARD_FILE_VERSION
    assert doc["cardPubkey"] == CARD_PUBKEY
    assert [s["amount"] for s in doc["slots"]] == [8, 16]

    parsed = cardctl.read_card_file(_write(doc))
    assert [s["amount"] for s in parsed["slots"]] == [8, 16]


def test_dump_uses_the_schema_field_names():
    assert set(_dump()["slots"][0]) == {"keysetId", "amount", "nonce", "C"}


def test_dump_writes_full_16_char_keyset_ids():
    for slot in _dump()["slots"]:
        assert len(slot["keysetId"]) == 16, slot["keysetId"]


def test_dump_includes_spent_slots_by_default():
    """A spent slot is still owed until it settles — dropping it loses money."""
    assert len(_dump()["slots"]) == 2


def test_dump_unspent_only_skips_spent_slots():
    assert len(_dump(extra=["--unspent-only"])["slots"]) == 1


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
