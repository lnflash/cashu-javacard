"""
APDU encoding tests for cardctl.

These assert the exact bytes cardctl puts on the wire against spec/APDU.md.
Worth having because the alternative is discovering an off-by-one in P1 or a
missing Le byte while hunched over a card reader, where every iteration costs a
re-tap and the failure looks identical to a hardware problem.

No reader and no card required — the PC/SC connection is faked.

Run:  python3 -m pytest test_apdu.py -q     (or: python3 test_apdu.py)
"""

import contextlib
import io
import secrets
import sys
import traceback
import types

import bip340
import cardctl


class FakeConnection:
    """Records transmitted APDUs and replays canned responses."""

    def __init__(self, responses=None):
        self.sent = []
        self.responses = list(responses or [])

    def connect(self):
        pass

    def transmit(self, apdu):
        self.sent.append(bytes(apdu))
        if self.responses:
            data, sw = self.responses.pop(0)
            return list(data), sw >> 8, sw & 0xFF
        return [], 0x90, 0x00

    @property
    def last(self):
        return self.sent[-1]


def make_card(responses=None):
    """A Card wired to a FakeConnection, bypassing PC/SC discovery."""
    card = cardctl.Card.__new__(cardctl.Card)
    card.connection = FakeConnection(responses)
    card.verbose = False
    card.reader = "fake"
    return card


# ── selection ─────────────────────────────────────────────────────────────────
def test_select_uses_7_byte_package_aid():
    card = make_card([(b"\x00\x01", 0x9000)])
    card.select()
    assert card.connection.last == bytes.fromhex("00A4040007D276000085010 2".replace(" ", "")), \
        card.connection.last.hex()


def test_select_falls_back_to_8_byte_applet_aid():
    # First SELECT fails (6A82), second must use the 8-byte AID.
    card = make_card([(b"", 0x6A82), (b"\x00\x01", 0x9000)])
    card.select()
    assert len(card.connection.sent) == 2
    assert card.connection.sent[1] == bytes.fromhex("00A404000 8D276000085010201".replace(" ", ""))


# ── read commands: exact bytes from spec/APDU.md ─────────────────────────────
def test_read_command_encodings():
    # Each canned response is long enough not to trip length checks; get_pubkey
    # additionally validates the point encoding, so its reply must parse.
    cases = [
        ("get_info", (), "B0010000 00", b"\x00" * 40),
        ("get_pubkey", (), "B0100000 21", b"\x02" + b"\x00" * 32),
        ("get_balance", (), "B0110000 04", b"\x00" * 40),
        ("get_proof_count", (), "B0120000 01", b"\x00" * 40),
        ("get_slot_status", (), "B0140000 20", b"\x00" * 40),
    ]
    for method, args, expected, response in cases:
        card = make_card([(response, 0x9000)])
        getattr(card, method)(*args)
        assert card.connection.last == bytes.fromhex(expected.replace(" ", "")), \
            f"{method}: {card.connection.last.hex()} != {expected}"


def test_get_pubkey_normalises_a_65_byte_card_to_33_bytes():
    # An applet built before GET_PUBKEY was fixed returns getW()'s 65-byte
    # uncompressed point on real silicon. Every consumer (sign, dump, load-file)
    # goes through Card.get_pubkey(), so the normalisation has to live there —
    # not in the verifier alone, or `dump` would write a 65-byte lock into the
    # card file that validate_card_doc then refuses to read back.
    x = bytes.fromhex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    y = bytes.fromhex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    uncompressed = b"\x04" + x + y
    card = make_card([(uncompressed, 0x9000), (uncompressed, 0x9000)])
    assert card.get_pubkey() == b"\x02" + x
    assert card.get_pubkey(raw=True) == uncompressed

    compressed = b"\x03" + x
    card = make_card([(compressed, 0x9000)])
    assert card.get_pubkey() == compressed

    card = make_card([(b"\x05" + x + y, 0x9000)])
    try:
        card.get_pubkey()
    except SystemExit as exc:
        assert "GET_PUBKEY" in str(exc)
    else:
        raise AssertionError("get_pubkey accepted a 65-byte blob without 0x04")


def test_get_proof_puts_slot_in_p1_and_asks_for_78_bytes():
    card = make_card([(b"\x01" + b"\x00" * 77, 0x9000)])
    card.get_proof(5)
    assert card.connection.last == bytes.fromhex("B0130500" + "4E")


def test_get_proof_parses_the_slot_layout():
    body = (
        b"\x01"                                   # status: unspent
        + bytes.fromhex("0059534ce0bfa19a")       # keyset id (8 RAW bytes)
        + (1234).to_bytes(4, "big")               # amount
        + bytes(range(32))                        # nonce
        + b"\x02" + bytes(range(32))              # C
    )
    assert len(body) == 78
    card = make_card([(body, 0x9000)])
    p = card.get_proof(0)
    assert p["status"] == "unspent"
    assert p["amount"] == 1234
    assert p["nonce"] == bytes(range(32))
    assert p["c"][0] == 0x02 and len(p["c"]) == 33


def test_get_proof_returns_the_full_16_char_keyset_id():
    """
    A NUT-02 keyset id is 16 hex chars. Decoding the 8 stored bytes as ASCII
    would yield only 8 chars — half an id, matching no keyset at the mint.
    """
    body = (
        b"\x01"
        + bytes.fromhex("0059534ce0bfa19a")
        + (1).to_bytes(4, "big")
        + bytes(32)
        + b"\x02" + bytes(32)
    )
    p = make_card([(body, 0x9000)]).get_proof(0)
    assert p["keyset_id"] == "0059534ce0bfa19a", p["keyset_id"]
    assert len(p["keyset_id"]) == 16


def test_parse_keyset_id_rejects_a_half_length_id():
    """Eight hex chars used to be ASCII-encoded, silently stranding the funds."""
    try:
        cardctl.parse_keyset_id("0059534c")
    except SystemExit as exc:
        assert "16" in str(exc), str(exc)
    else:
        raise AssertionError("expected SystemExit for a truncated keyset id")


def test_parse_keyset_id_accepts_a_full_id():
    assert cardctl.parse_keyset_id("0059534ce0bfa19a") == bytes.fromhex("0059534ce0bfa19a")
    # case-insensitive
    assert cardctl.parse_keyset_id("0059534CE0BFA19A") == bytes.fromhex("0059534ce0bfa19a")


def test_parse_keyset_id_does_not_claim_truncation_for_non_hex():
    """An 8-char value that is not hex was never half an id. Saying so sends the
    operator hunting for a truncation that never happened."""
    try:
        cardctl.parse_keyset_id("hellooo1")
    except SystemExit as exc:
        assert "not valid hex" in str(exc), str(exc)
    else:
        raise AssertionError("expected SystemExit for a non-hex keyset id")


def test_get_info_decodes_capabilities_and_pin_state():
    # v0.1, 32 slots, 3 unspent, 1 spent, 28 empty, caps=0x03, pin=set
    card = make_card([(bytes([0, 1, 32, 3, 1, 28, 0x03, 1]), 0x9000)])
    i = card.get_info()
    assert i["version"] == "0.1" and i["max_slots"] == 32
    assert i["unspent"] == 3 and i["spent"] == 1 and i["empty"] == 28
    assert i["secp256k1_native"] and i["schnorr"]
    assert i["clear_pin"] is False, "bit 3 clear: a pre-0.5 card has no CLEAR_PIN"
    assert i["pin_state"] == "set"

    assert i["unblock_pin"] is False, "bit 4 clear: a pre-0.6 card has no PUK"
    assert i["puk_state"] is None, "eight bytes: there is no PUK state to report"
    assert i["pin_state"] == "set"

    # v0.5 answers caps=0x0F: bit 3 is CLEAR_PIN (spec/APDU.md, GET_INFO).
    i = make_card([(bytes([0, 5, 32, 0, 0, 32, 0x0F, 0]), 0x9000)]).get_info()
    assert i["version"] == "0.5" and i["clear_pin"] is True and i["unblock_pin"] is False
    assert i["secp256k1_native"] and i["schnorr"]
    assert i["pin_state"] == "unset" and i["puk_state"] is None

    # v0.6 answers nine bytes and caps=0x1F: bit 4 is the PUK, byte 8 its
    # state (D16). None of the first eight bytes moved.
    for state, name in ((0, "unset"), (1, "set"), (2, "exhausted")):
        i = make_card([(bytes([0, 6, 32, 3, 1, 28, 0x1F, 1, state]), 0x9000)]).get_info()
        assert i["version"] == "0.6" and i["unblock_pin"] is True and i["clear_pin"] is True
        assert i["unspent"] == 3 and i["spent"] == 1 and i["empty"] == 28
        assert i["pin_state"] == "set" and i["puk_state"] == name, (state, i)
    i = make_card([(bytes([0, 6, 32, 0, 0, 32, 0x1F, 0, 7]), 0x9000)]).get_info()
    assert i["puk_state"] == "unknown(7)"


def test_cmd_info_names_the_clear_pin_capability():
    card = make_card([(bytes([0, 5, 32, 0, 0, 32, 0x0F, 1]), 0x9000), (bytes(4), 0x9000)])
    args = cardctl.build_parser().parse_args(["info"])
    with stubbed_connect(card) as out:
        assert args.func(args) == 0
    assert "clear_pin=True" in out.getvalue(), out.getvalue()
    assert "unblock_pin=False" in out.getvalue(), out.getvalue()
    assert "PUK              : none (applet 0.5 has no PUK; added in 0.6)" in out.getvalue(), out.getvalue()


def test_cmd_info_names_the_puk_capability_and_state():
    for state, text in ((0, "unset"), (1, "set"), (2, "exhausted (ten wrong PUKs")):
        card = make_card([(bytes([0, 6, 32, 0, 0, 32, 0x1F, 1, state]), 0x9000), (bytes(4), 0x9000)])
        args = cardctl.build_parser().parse_args(["info"])
        with stubbed_connect(card) as out:
            assert args.func(args) == 0
        assert "unblock_pin=True" in out.getvalue(), out.getvalue()
        assert f"PUK              : {text}" in out.getvalue(), out.getvalue()


# ── spend commands ───────────────────────────────────────────────────────────
def test_spend_proof_encoding():
    msg = bytes(range(32))
    card = make_card([(b"\x00" * 64, 0x9000)])
    card.spend_proof(3, msg)
    expected = bytes.fromhex("B0200300") + bytes([0x20]) + msg + bytes([0x40])
    assert card.connection.last == expected


def test_sign_arbitrary_encoding():
    msg = bytes(range(32))
    card = make_card([(b"\x00" * 64, 0x9000)])
    card.sign(msg)
    expected = bytes.fromhex("B0210000") + bytes([0x20]) + msg + bytes([0x40])
    assert card.connection.last == expected


# ── write commands ───────────────────────────────────────────────────────────
def test_load_proof_builds_a_77_byte_payload():
    card = make_card([(b"\x07", 0x9000)])
    keyset = bytes.fromhex("0059534ce0bfa19a")
    slot = card.load_proof(keyset, 4096, bytes(range(32)), b"\x02" + bytes(range(32)))
    assert slot == 7
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0300000")
    assert sent[4] == 0x4D, f"Lc should be 77, got {sent[4]}"
    payload = sent[5:5 + 77]
    assert payload[:8] == keyset
    assert int.from_bytes(payload[8:12], "big") == 4096
    assert sent[-1] == 0x01  # Le


def test_load_proof_round_trips_the_keyset_id_through_get_proof():
    """What load writes must be what get_proof reads back — the seam that
    decides whether a proof can be matched to a keyset at the mint."""
    keyset_hex = "008288762774ace1"
    keyset = cardctl.parse_keyset_id(keyset_hex)
    card = make_card([(b"\x00", 0x9000)])
    card.load_proof(keyset, 8, bytes(32), b"\x02" + bytes(32))
    written = card.connection.last[5:5 + 8]

    body = b"\x01" + written + (8).to_bytes(4, "big") + bytes(32) + b"\x02" + bytes(32)
    read_back = make_card([(body, 0x9000)]).get_proof(0)
    assert read_back["keyset_id"] == keyset_hex, read_back["keyset_id"]


def test_clear_spent_encoding():
    card = make_card([(b"\x04", 0x9000)])
    assert card.clear_spent() == 4
    assert card.connection.last == bytes.fromhex("B0310000" + "01")


# ── auth ─────────────────────────────────────────────────────────────────────
def test_verify_pin_encoding():
    card = make_card()
    card.verify_pin(b"1234")
    assert card.connection.last == bytes.fromhex("B0400000") + bytes([4]) + b"1234"


def test_change_pin_prefixes_the_old_pin_length():
    card = make_card()
    card.change_pin(b"1234", b"567890")
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0420000")
    assert sent[4] == 1 + 4 + 6      # Lc
    assert sent[5] == 4              # old PIN length prefix
    assert sent[6:10] == b"1234"
    assert sent[10:16] == b"567890"


def test_clear_pin_prefixes_the_pin_length_and_sends_nothing_after_it():
    card = make_card()
    card.clear_pin(b"567890")
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0430000")
    assert sent[4] == 1 + 6            # Lc: exactly one more than the PIN
    assert sent[5] == 6                # PIN length prefix
    assert sent[6:12] == b"567890"
    assert len(sent) == 12, "no Le, no trailing bytes: the card refuses Lc != 1 + len with 6700"


def test_cmd_clear_pin_verifies_first_then_clears_with_the_same_pin():
    """The order the card requires (spec/APDU.md, CLEAR_PIN): VERIFY_PIN opens
    the session, then CLEAR_PIN carries the PIN again. Sending CLEAR_PIN alone
    is 6982 on every card, and a wrong PIN in it costs a try."""
    info = bytes([0, 5, 32, 0, 0, 32, 0x0F, 1])
    card = make_card([(info, 0x9000), (b"", 0x9000), (b"", 0x9000)])
    args = cardctl.build_parser().parse_args(["clear-pin", "--pin", "1234"])
    with stubbed_connect(card) as out:
        assert args.func(args) == 0
    sent = card.connection.sent
    assert [apdu[1] for apdu in sent] == [
        cardctl.INS_GET_INFO, cardctl.INS_VERIFY_PIN, cardctl.INS_CLEAR_PIN,
    ], [apdu.hex() for apdu in sent]
    assert sent[1][5:9] == b"1234"
    assert sent[2] == bytes.fromhex("B0430000") + bytes([5, 4]) + b"1234"
    assert "PIN cleared" in out.getvalue(), out.getvalue()


def test_cmd_clear_pin_refuses_a_card_without_the_capability_before_verifying():
    """A 0.4 card answers CLEAR_PIN with 6D00, which reads like a bad INS byte.
    The capability bit says so first, and no VERIFY_PIN is spent on it."""
    info = bytes([0, 4, 32, 0, 0, 32, 0x07, 1])
    card = make_card([(info, 0x9000)])
    args = cardctl.build_parser().parse_args(["clear-pin", "--pin", "1234"])
    with stubbed_connect(card):
        try:
            args.func(args)
        except SystemExit as exc:
            assert "no CLEAR_PIN" in str(exc) and "0.4" in str(exc), str(exc)
        else:
            raise AssertionError("clear-pin ran against a card without the capability")
    assert [apdu[1] for apdu in card.connection.sent] == [cardctl.INS_GET_INFO]


def test_clear_pin_requires_the_pin_flag():
    try:
        cardctl.build_parser().parse_args(["clear-pin"])
    except SystemExit:
        pass
    else:
        raise AssertionError("clear-pin parsed without --pin")


# ── PUK (D16) ────────────────────────────────────────────────────────────────
INFO_06_NO_PIN_NO_PUK = bytes([0, 6, 32, 0, 0, 32, 0x1F, 0, 0])
INFO_06_PIN_NO_PUK = bytes([0, 6, 32, 0, 0, 32, 0x1F, 1, 0])
INFO_06_PIN_PUK = bytes([0, 6, 32, 0, 0, 32, 0x1F, 1, 1])
INFO_06_BLOCKED_PUK = bytes([0, 6, 32, 0, 0, 32, 0x1F, 2, 1])
INFO_06_BLOCKED_NO_PUK = bytes([0, 6, 32, 0, 0, 32, 0x1F, 2, 0])
INFO_06_PIN_PUK_EXHAUSTED = bytes([0, 6, 32, 0, 0, 32, 0x1F, 1, 2])
# A PUK with no PIN: not a personalisation state, since the order is SET_PUK
# then SET_PIN with nothing issued between — a card that reports this to a
# personaliser was armed by someone else (SECURITY-MODEL #16).
INFO_06_NO_PIN_PUK = bytes([0, 6, 32, 0, 0, 32, 0x1F, 0, 1])
INFO_05_PIN = bytes([0, 5, 32, 0, 0, 32, 0x0F, 1])


def test_set_puk_prefixes_the_puk_length_and_sends_nothing_after_it():
    card = make_card()
    card.set_puk(b"123456789012")
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0440000")
    assert sent[4] == 1 + 12          # Lc: exactly one more than the PUK
    assert sent[5] == 12              # PUK length prefix
    assert sent[6:18] == b"123456789012"
    assert len(sent) == 18, "no Le, no trailing bytes: the card refuses Lc != 1 + len with 6700"


def test_unblock_pin_frames_the_puk_and_the_new_pin_each_with_a_length():
    card = make_card()
    card.unblock_pin(b"12345678", b"5678")
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0450000")
    assert sent[4] == 2 + 8 + 4       # Lc: both prefixes, both values
    assert sent[5] == 8 and sent[6:14] == b"12345678"
    assert sent[14] == 4 and sent[15:19] == b"5678"
    assert len(sent) == 19, "no Le, no trailing bytes"


def _run(card, *argv):
    args = cardctl.build_parser().parse_args(list(argv))
    with stubbed_connect(card) as out:
        rc = args.func(args)
    return rc, out.getvalue()


def _refuses(card, *argv):
    """Run and return the SystemExit message, failing if the command ran."""
    args = cardctl.build_parser().parse_args(list(argv))
    with stubbed_connect(card):
        try:
            args.func(args)
        except SystemExit as exc:
            return str(exc)
    raise AssertionError(f"{argv} ran against a card it should have refused")


def test_cmd_set_puk_on_a_no_pin_card_sends_set_puk_alone():
    """The personalisation order (spec/APDU.md, Personalisation): SET_PUK on
    a card with no PIN needs no session, so no VERIFY_PIN is sent."""
    card = make_card([(INFO_06_NO_PIN_NO_PUK, 0x9000), (b"", 0x9000)])
    rc, out = _run(card, "set-puk", "--puk", "12345678")
    assert rc == 0
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO, cardctl.INS_SET_PUK]
    assert card.connection.sent[1] == bytes.fromhex("B0440000") + bytes([9, 8]) + b"12345678"
    assert "PUK set" in out and "record it off the card" in out, out


def test_cmd_set_puk_on_a_pin_card_verifies_first_and_needs_the_pin_flag():
    """The other order: SET_PIN, VERIFY_PIN, SET_PUK. The card answers 6982
    without the session, so the tool asks for --pin up front rather than
    sending a SET_PUK it knows will be refused."""
    card = make_card([(INFO_06_PIN_NO_PUK, 0x9000), (b"", 0x9000), (b"", 0x9000)])
    rc, out = _run(card, "set-puk", "--puk", "12345678", "--pin", "1234")
    assert rc == 0, out
    assert [a[1] for a in card.connection.sent] == [
        cardctl.INS_GET_INFO, cardctl.INS_VERIFY_PIN, cardctl.INS_SET_PUK,
    ]
    assert card.connection.sent[1][5:9] == b"1234"

    card = make_card([(INFO_06_PIN_NO_PUK, 0x9000)])
    msg = _refuses(card, "set-puk", "--puk", "12345678")
    assert "pass --pin" in msg, msg
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO]


def test_cmd_set_puk_refuses_what_the_card_would_refuse_before_sending():
    # A PUK already set (or exhausted): 6A89 on the card, said here first.
    for info, word in ((INFO_06_PIN_PUK, "set"), (INFO_06_PIN_PUK_EXHAUSTED, "exhausted")):
        card = make_card([(info, 0x9000)])
        msg = _refuses(card, "set-puk", "--puk", "12345678", "--pin", "1234")
        assert f"already {word}" in msg, msg
        assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO], "nothing was sent"
    # A blocked PIN with no PUK: 6982 on the card in every session, and the
    # balance is stranded. No VERIFY_PIN is spent finding that out.
    card = make_card([(INFO_06_BLOCKED_NO_PUK, 0x9000)])
    msg = _refuses(card, "set-puk", "--puk", "12345678", "--pin", "1234")
    assert "blocked" in msg and "stranded" in msg, msg
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO]
    # A 0.5 card answers 0x44 with 6D00; the capability bit says so first.
    card = make_card([(INFO_05_PIN, 0x9000)])
    msg = _refuses(card, "set-puk", "--puk", "12345678", "--pin", "1234")
    assert "no SET_PUK" in msg and "0.5" in msg and "0.6" in msg, msg
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO]


def test_cmd_set_puk_names_a_foreign_puk_on_a_card_with_no_pin():
    """A PUK on a card with no PIN is one the personaliser did not set: SET_PUK
    is free at pinState 0, so anyone who touched the card pre-issuance could
    have armed it, and would then own the PIN via UNBLOCK_PIN after three wrong
    PINs (SECURITY-MODEL #16). "Already set" reads as a benign re-run; this
    must read as a card not to issue."""
    for argv in (("set-puk", "--puk", "12345678"),
                 ("set-puk", "--puk", "12345678", "--pin", "1234")):
        card = make_card([(INFO_06_NO_PIN_PUK, 0x9000)])
        msg = _refuses(card, *argv)
        assert "reports a PUK but has no PIN" in msg, msg
        assert "someone else did" in msg and "do not issue this card" in msg, msg
        assert "reinstall the CAP" in msg and "cannot be replaced" in msg, msg
        assert "already set" not in msg, "must not read as a duplicate run: " + msg
        assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO], "nothing was sent"
    # A PUK on a card that has a PIN is the ordinary duplicate-run case and
    # keeps its wording: the holder's session was needed to attach it.
    card = make_card([(INFO_06_PIN_PUK, 0x9000)])
    msg = _refuses(card, "set-puk", "--puk", "12345678", "--pin", "1234")
    assert "already set" in msg and "someone else" not in msg, msg


def test_cmd_set_puk_ignores_the_pin_flag_on_a_card_with_no_pin():
    """A fresh card answers VERIFY_PIN with 6984, so sending it would abort a
    SET_PUK the card was going to accept. A personalisation script that passes
    --pin uniformly must still work on every blank card: GET_INFO, SET_PUK,
    nothing between, and a notice that the flag went unused."""
    card = make_card([(INFO_06_NO_PIN_NO_PUK, 0x9000), (b"", 0x9000)])
    rc, out = _run(card, "set-puk", "--puk", "12345678", "--pin", "1234")
    assert rc == 0, out
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO, cardctl.INS_SET_PUK]
    assert card.connection.sent[1] == bytes.fromhex("B0440000") + bytes([9, 8]) + b"12345678"
    assert "--pin ignored" in out and "no PIN" in out, out
    assert "PUK set" in out, out
    # And without --pin there is no notice to give.
    card = make_card([(INFO_06_NO_PIN_NO_PUK, 0x9000), (b"", 0x9000)])
    rc, out = _run(card, "set-puk", "--puk", "12345678")
    assert rc == 0 and "ignored" not in out, out


def test_cmd_unblock_pin_names_the_puk_and_its_counter_on_a_wrong_puk():
    """63CX from UNBLOCK_PIN counts PUK tries, not PIN retries. An operator
    who reads "wrong PIN — 9 retries remaining" re-checks --new-pin and burns
    PUK tries that are terminal at zero (#15); the message must send them to
    --puk."""
    card = make_card([(INFO_06_PIN_PUK, 0x9000), (b"", 0x63C9)])
    args = cardctl.build_parser().parse_args(
        ["unblock-pin", "--puk", "12345678", "--new-pin", "5678"])
    with stubbed_connect(card):
        try:
            args.func(args)
        except cardctl.CardError as exc:
            msg = str(exc)
        else:
            raise AssertionError("expected CardError on 63C9")
    assert "63C9" in msg and "during UNBLOCK_PIN" in msg, msg
    assert "wrong PUK" in msg and "9 PUK tries remaining" in msg, msg
    assert "exhausted for good" in msg, msg
    meaning = msg.split(": ", 1)[1]           # after "card returned 63C9 during UNBLOCK_PIN: "
    assert "PIN" not in meaning, "the meaning must not name the PIN: " + msg
    # Exhaustion from UNBLOCK_PIN is the PUK's, for good.
    card = make_card([(INFO_06_PIN_PUK, 0x9000), (b"", 0x6983)])
    with stubbed_connect(card):
        try:
            args.func(args)
        except cardctl.CardError as exc:
            msg = str(exc)
        else:
            raise AssertionError("expected CardError on 6983")
    assert "PUK exhausted" in msg and "for good" in msg, msg
    assert not msg.split(": ", 1)[1].startswith("PIN blocked"), msg


def test_cmd_unblock_pin_sends_unblock_pin_alone_with_no_verify():
    """No VERIFY_PIN: the PUK is the authority, and a blocked card cannot
    open a session anyway (spec/APDU.md, UNBLOCK_PIN)."""
    for info in (INFO_06_BLOCKED_PUK, INFO_06_PIN_PUK):
        card = make_card([(info, 0x9000), (b"", 0x9000)])
        rc, out = _run(card, "unblock-pin", "--puk", "12345678", "--new-pin", "5678")
        assert rc == 0, out
        assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO, cardctl.INS_UNBLOCK_PIN]
        assert card.connection.sent[1] == (
            bytes.fromhex("B0450000") + bytes([14, 8]) + b"12345678" + bytes([4]) + b"5678"
        )
        assert "PIN replaced" in out and "VERIFY_PIN with the new PIN" in out, out


def test_cmd_unblock_pin_refuses_what_the_card_would_refuse_before_spending_a_try():
    # No PUK: 6A82 on the card. On a blocked card that is the stranded case.
    card = make_card([(INFO_06_BLOCKED_NO_PUK, 0x9000)])
    msg = _refuses(card, "unblock-pin", "--puk", "12345678", "--new-pin", "5678")
    assert "no PUK" in msg and "stranded" in msg, msg
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO]
    card = make_card([(INFO_06_PIN_NO_PUK, 0x9000)])
    msg = _refuses(card, "unblock-pin", "--puk", "12345678", "--new-pin", "5678")
    assert "no PUK" in msg and "stranded" not in msg, msg
    # Exhausted: 6983 on the card, for good; a wrong guess here would be
    # pointless and a right one too.
    card = make_card([(INFO_06_PIN_PUK_EXHAUSTED, 0x9000)])
    msg = _refuses(card, "unblock-pin", "--puk", "12345678", "--new-pin", "5678")
    assert "exhausted" in msg and "6983" in msg, msg
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO]
    # No PIN: 6984 on the card; set-pin is the way.
    card = make_card([(bytes([0, 6, 32, 0, 0, 32, 0x1F, 0, 1]), 0x9000)])
    msg = _refuses(card, "unblock-pin", "--puk", "12345678", "--new-pin", "5678")
    assert "no PIN" in msg and "set-pin" in msg, msg
    # A 0.5 card answers 0x45 with 6D00.
    card = make_card([(INFO_05_PIN, 0x9000)])
    msg = _refuses(card, "unblock-pin", "--puk", "12345678", "--new-pin", "5678")
    assert "no UNBLOCK_PIN" in msg and "0.5" in msg, msg
    assert [a[1] for a in card.connection.sent] == [cardctl.INS_GET_INFO]


def test_puk_commands_require_their_flags():
    for argv in (["set-puk"], ["unblock-pin"], ["unblock-pin", "--puk", "12345678"],
                 ["unblock-pin", "--new-pin", "5678"]):
        try:
            cardctl.build_parser().parse_args(argv)
        except SystemExit:
            pass
        else:
            raise AssertionError(f"{argv} parsed without its required flags")


def test_lock_card_sends_the_confirmation_byte_in_p2():
    card = make_card()
    card.lock_card()
    assert card.connection.last == bytes.fromhex("B05000DE")


# ── CLI wiring ───────────────────────────────────────────────────────────────
# The bug this file exists to prevent lived in cmd_load, not in the helpers it
# calls. Testing parse_keyset_id and Card.load_proof in isolation leaves the one
# line that carried the defect uncovered: a rename of --nonce, or a restored
# `args.keyset.encode()`, keeps every other test green while every loaded proof
# goes back to being unspendable. These drive the real parser into the real
# command, with only the PC/SC connection faked.

@contextlib.contextmanager
def stubbed_connect(card):
    """Point cardctl.connect at a FakeConnection-backed Card.

    Captures the command's own stdout — so the standalone runner's PASS/FAIL
    lines stay readable — and yields the buffer, so a test that cares what the
    command printed can assert on it.
    """
    real = cardctl.connect
    cardctl.connect = lambda args: card
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            yield buf
    finally:
        cardctl.connect = real


def test_cmd_load_puts_the_raw_16_char_keyset_id_on_the_wire():
    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "16"]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0300000")
    assert sent[5:13] == bytes.fromhex("0059534ce0bfa19a"), sent[5:13].hex()
    assert int.from_bytes(sent[13:17], "big") == 16, sent[13:17].hex()


def test_cmd_load_accepts_an_on_curve_explicit_c_and_keeps_the_placeholder():
    """The curve check on --c must not break either legitimate path.

    An explicit on-curve C (a real mint signature) must reach the wire
    unchanged, and the no---c placeholder workflow documented for storage
    testing must survive — the placeholder is random and deliberately exempt
    from the curve check, because nothing will ever try to spend it.
    """
    on_curve = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "16",
         "--c", on_curve]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0
    assert card.connection.last[5 + 44:5 + 77] == bytes.fromhex(on_curve), \
        card.connection.last.hex()

    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "16"]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0, "placeholder default must still load"


def test_cmd_load_rejects_a_half_length_keyset_id():
    card = make_card([(b"\x03", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534c", "--amount", "16"]
    )
    with stubbed_connect(card):
        try:
            args.func(args)
        except SystemExit as exc:
            assert "16" in str(exc), str(exc)
        else:
            raise AssertionError("cmd_load accepted a half-length keyset id")
    assert card.connection.sent == [], "nothing should reach the card"


def test_cmd_load_validates_arguments_before_opening_the_reader():
    """A bad --keyset must cost nothing — not even a PIN attempt.

    VERIFY_PIN decrements the card's retry counter and locks the card after a
    few misses. If cmd_load connects and verifies before parsing, then
    `load --keyset 0059534c --pin 4321` burns a retry on a command that could
    never have succeeded. The previous test only proves this by accident: it
    passes no --pin, so the VERIFY_PIN branch is never reached regardless of
    ordering. This one passes one, and also asserts the reader was never opened
    — the transmit log alone cannot distinguish "did not connect" from
    "connected and sent nothing".
    """
    bad = [
        # a half-length keyset id, and a nonce that is 31 bytes instead of 32
        ["--keyset", "0059534c", "--amount", "16", "--pin", "4321"],
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--nonce", "00" * 31],
        # ...and a C that is 32 bytes instead of the compressed-point 33
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--c", "00" * 32],
        # ...and a 33-byte C with a bad prefix, and one whose x is not on the
        # curve. The file path (`_slot_from_json`) refuses both; an explicit
        # --c must be held to the same rule, or a typo burns a slot on money
        # nothing can spend and `dump` then refuses the whole card.
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--c", "05" + "cd" * 32],
        ["--keyset", "0059534ce0bfa19a", "--amount", "16", "--pin", "4321",
         "--c", "02" + "cd" * 32],
        # ...and the three amounts the card's 4-byte field or a mint keyset
        # cannot represent. These used to reach the card: 2**32 died on a bare
        # OverflowError out of load_proof, and 0 burned a slot on a worthless
        # proof, both after VERIFY_PIN had already spent a retry.
        ["--keyset", "0059534ce0bfa19a", "--amount", "4294967296", "--pin", "4321"],
        ["--keyset", "0059534ce0bfa19a", "--amount", "0", "--pin", "4321"],
        ["--keyset", "0059534ce0bfa19a", "--amount", "5", "--pin", "4321"],
    ]
    for flags in bad:
        card = make_card([(b"\x03", 0x9000)])
        args = cardctl.build_parser().parse_args(["load", *flags])
        connects = []
        real = cardctl.connect
        cardctl.connect = lambda a: (connects.append(a), card)[1]
        try:
            try:
                args.func(args)
            except SystemExit:
                pass
            else:
                raise AssertionError(f"cmd_load accepted bad arguments: {flags}")
        finally:
            cardctl.connect = real
        assert connects == [], f"cmd_load opened the reader before validating: {flags}"
        assert card.connection.sent == [], \
            f"cmd_load transmitted before validating {flags}: " \
            f"{[a.hex() for a in card.connection.sent]}"


def test_cmd_load_reads_the_nonce_flag_it_declares():
    """cmd_load reads args.nonce; build_parser must declare --nonce. Renaming
    either half alone is an AttributeError at the card reader, not in CI."""
    # A distinctive value, not zeros: bytes(32) is the one nonce that a
    # hard-coded `nonce = bytes(32)` in cmd_load would also produce, so
    # asserting on it would pass with the flag-reading deleted.
    nonce = bytes(range(32))
    card = make_card([(b"\x00", 0x9000)])
    args = cardctl.build_parser().parse_args(
        ["load", "--keyset", "0059534ce0bfa19a", "--amount", "1", "--nonce", nonce.hex()]
    )
    with stubbed_connect(card):
        assert args.func(args) == 0
    assert card.connection.last[17:49] == nonce, card.connection.last[17:49].hex()


def test_cmd_load_generates_a_fresh_nonce_per_proof():
    """A constant nonce makes every reconstructed P2PK secret identical, which is
    what SPEND_PROOF replay resistance rests on (spec/APDU.md)."""
    seen = []
    for _ in range(2):
        card = make_card([(b"\x00", 0x9000)])
        args = cardctl.build_parser().parse_args(
            ["load", "--keyset", "0059534ce0bfa19a", "--amount", "1"]
        )
        with stubbed_connect(card):
            assert args.func(args) == 0
        seen.append(card.connection.last[17:49])
    assert seen[0] != seen[1], f"nonce is not fresh per proof: {seen[0].hex()}"
    assert seen[0] != bytes(32), "nonce is all zeros"


def test_load_parser_no_longer_accepts_keyset_hex():
    """--keyset-hex selected the ASCII path this PR deleted. It must stay gone,
    or a stale runbook silently re-enables half-id encoding.

    A bare `except SystemExit: pass` would not prove that: argparse exits 2 for
    any parser failure, so renaming --keyset would keep this green while saying
    nothing about --keyset-hex. Assert on the message argparse actually wrote.
    """
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        try:
            cardctl.build_parser().parse_args(
                ["load", "--keyset", "0059534ce0bfa19a", "--amount", "1", "--keyset-hex"]
            )
        except SystemExit:
            pass
        else:
            raise AssertionError("--keyset-hex is still accepted")
    assert "unrecognized arguments: --keyset-hex" in buf.getvalue(), buf.getvalue()


def test_cmd_proof_prints_the_full_keyset_id_and_the_nonce():
    """The read side of the same seam. cmd_proof indexes p['keyset_id'] and
    p['nonce'] out of a dict Card.get_proof builds ~120 lines away; renaming
    either half alone is a KeyError in front of a card, with no CI signal.

    Distinctive values on both fields: a nonce of zeros would still match a
    cmd_proof that printed a constant, and the keyset id is asserted at its
    full 16 chars so an ASCII-decoding regression (8 chars) fails here too.
    """
    nonce = bytes(range(32, 64))
    body = (
        b"\x01"
        + bytes.fromhex("0059534ce0bfa19a")
        + (4242).to_bytes(4, "big")
        + nonce
        + b"\x02" + bytes(range(32))
    )
    assert len(body) == 78
    card = make_card([(body, 0x9000)])
    args = cardctl.build_parser().parse_args(["proof", "0"])
    with stubbed_connect(card) as out:
        assert args.func(args) == 0
    printed = out.getvalue()
    assert "0059534ce0bfa19a" in printed, printed
    assert nonce.hex() in printed.lower(), printed
    assert "4242" in printed, printed


# ── selftest against a model of the applet's PIN gate ────────────────────────
# selftest decides its next APDU from the last answer, so a list of canned
# responses cannot drive it. These tests run the real command against a small
# model of the applet instead: GET_INFO's PIN state, VERIFY_PIN's counter and
# the gate on SIGN_ARBITRARY. The model signs for real (BIP-340), so a selftest
# that reaches the signing rounds on a card it should have stopped at shows up
# as a pass, not as a garbage signature that fails for the wrong reason.

_CARD_SECKEY = 0x1F0E2D3C4B5A69788796A5B4C3D2E1F00112233445566778899AABBCCDDEEFF0


def _bip340_sign(seckey: int, msg: bytes) -> bytes:
    """BIP-340 signing with fresh aux randomness, standing in for the card."""
    n = bip340.N
    pub = bip340._point_mul(bip340.G, seckey)
    d = seckey if pub[1] % 2 == 0 else n - seckey
    px = pub[0].to_bytes(32, "big")
    aux = bip340.tagged_hash("BIP0340/aux", secrets.token_bytes(32))
    t = (d ^ int.from_bytes(aux, "big")).to_bytes(32, "big")
    k0 = int.from_bytes(bip340.tagged_hash("BIP0340/nonce", t + px + msg), "big") % n
    r = bip340._point_mul(bip340.G, k0)
    k = k0 if r[1] % 2 == 0 else n - k0
    rx = r[0].to_bytes(32, "big")
    e = int.from_bytes(bip340.tagged_hash("BIP0340/challenge", rx + px + msg), "big") % n
    return rx + ((k + e * d) % n).to_bytes(32, "big")


class FakeApplet:
    """
    A PC/SC connection answering like the applet's PIN gate.

    `pin_state` is GET_INFO byte 7 (0 unset, 1 set, 2 blocked). `gate` picks
    the rule SIGN_ARBITRARY is gated by: "0.3" (the rule from applet 0.3 on)
    refuses whenever a PIN exists and the session is unverified; "0.2" is the
    ENG-615 rule, `pinState == 1`, which opens the moment the PIN is blocked.
    """

    def __init__(self, version=(0, 4), pin_state=1, pin=b"1234", gate="0.3", puk_state=0):
        self.version = bytes(version)
        self.pin_state = pin_state
        # GET_INFO byte 8, answered by 0.6 and later only (D16).
        self.puk_state = puk_state
        self.pin = pin
        self.tries = 3 if pin_state == 1 else 0
        self.verified = False
        self.gate = gate
        self.sent = []
        pub = bip340._point_mul(bip340.G, _CARD_SECKEY)
        self.pubkey = bytes([2 | (pub[1] & 1)]) + pub[0].to_bytes(32, "big")

    def connect(self):
        pass

    @property
    def ins_sent(self):
        """INS of every APDU after SELECT, in order."""
        return [apdu[1] for apdu in self.sent if apdu[:2] != b"\x00\xA4"]

    def transmit(self, apdu):
        apdu = bytes(apdu)
        self.sent.append(apdu)
        body, sw = self._answer(apdu)
        return list(body), sw >> 8, sw & 0xFF

    def _answer(self, apdu):
        if apdu[:2] == b"\x00\xA4":
            return self.version, 0x9000
        ins = apdu[1]
        if ins == cardctl.INS_GET_INFO:
            if tuple(self.version) >= (0, 6):
                return self.version + bytes([32, 0, 0, 32, 0x1F, self.pin_state, self.puk_state]), 0x9000
            return self.version + bytes([32, 0, 0, 32, 0x07, self.pin_state]), 0x9000
        if ins == cardctl.INS_GET_PUBKEY:
            return self.pubkey, 0x9000
        if ins == cardctl.INS_GET_BALANCE:
            return (21).to_bytes(4, "big"), 0x9000
        if ins == cardctl.INS_GET_SLOT_STATUS:
            return bytes(32), 0x9000
        if ins == cardctl.INS_VERIFY_PIN:
            if self.pin_state == 0:
                return b"", 0x6984
            if self.tries == 0:
                return b"", 0x6983
            if apdu[5:5 + apdu[4]] == self.pin:
                self.verified, self.tries = True, 3
                return b"", 0x9000
            self.verified, self.tries = False, self.tries - 1
            if self.tries == 0:
                self.pin_state = 2
                return b"", 0x6983
            return b"", 0x63C0 | self.tries
        if ins == cardctl.INS_SIGN_ARBITRARY:
            has_pin = self.pin_state != 0 if self.gate == "0.3" else self.pin_state == 1
            if has_pin and not self.verified:
                return b"", 0x6982
            return _bip340_sign(_CARD_SECKEY, apdu[5:37]), 0x9000
        return b"", 0x6D00


def run_selftest(applet, *flags):
    """Run `cardctl selftest <flags>` against `applet`; (exit code, stdout)."""
    card = cardctl.Card.__new__(cardctl.Card)
    card.connection = applet
    card.verbose = False
    card.reader = "fake"
    args = cardctl.build_parser().parse_args(["selftest", *flags])
    real = cardctl.Card
    cardctl.Card = lambda *a, **kw: card
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = args.func(args)
    finally:
        cardctl.Card = real
    return rc, buf.getvalue()


def test_selftest_verifies_a_set_pin_before_signing_and_passes():
    """The path the blocked-PIN branch must not swallow: a set PIN is verified
    before the first signing round, and every signature off the card verifies.
    Also proves the model signs for real, which the tests below rely on."""
    applet = FakeApplet(pin_state=1)
    rc, out = run_selftest(applet, "--pin", "1234")
    assert rc == 0, out
    assert "All 11 checks passed" in out, out
    ins = applet.ins_sent
    assert cardctl.INS_VERIFY_PIN in ins, ins
    assert ins.index(cardctl.INS_VERIFY_PIN) < ins.index(cardctl.INS_SIGN_ARBITRARY), ins


def test_selftest_stops_at_a_blocked_pin_before_any_signing_round():
    """
    GET_INFO byte 7 = 2 is a PIN that exists and can never verify, never "no
    PIN" (spec/APDU.md, GET_INFO). selftest used to handle it exactly like 0:
    `selftest --pin 1234` dropped the PIN without a word, passed six checks,
    then died on SIGN_ARBITRARY's 6982, which pointed the operator at a PIN
    that can never verify. It must fail the card, say why, and sign nothing.
    """
    applet = FakeApplet(pin_state=2)
    rc, out = run_selftest(applet, "--pin", "1234")
    assert rc == 1, out
    assert cardctl.INS_SIGN_ARBITRARY not in applet.ins_sent, "a signing round ran on a blocked card"
    assert cardctl.INS_VERIFY_PIN not in applet.ins_sent, "VERIFY_PIN cannot succeed on a blocked card"
    assert "FAIL  PIN state" in out, out
    assert "balance stranded (SECURITY-MODEL #14)" in out, out
    assert "1 check(s) FAILED: PIN state" in out, out
    # The reads still ran, so the operator sees the balance at stake.
    for ins in (cardctl.INS_GET_PUBKEY, cardctl.INS_GET_BALANCE, cardctl.INS_GET_SLOT_STATUS):
        assert ins in applet.ins_sent, f"INS {ins:02X} was not sent"


def test_selftest_fails_a_blocked_card_below_0_3_whose_gate_is_open():
    """
    On 0.1 and 0.2 a blocked PIN removed the gate (ENG-615). The old selftest
    skipped VERIFY_PIN, SIGN_ARBITRARY signed without a PIN, and the card
    passed every check: a card anyone could spend, reported healthy. It must
    fail, and name the fix, which is the opposite of a 0.3 card's: the balance
    is not stranded, so sweep it and reinstall.
    """
    applet = FakeApplet(version=(0, 2), pin_state=2, gate="0.2")
    rc, out = run_selftest(applet)
    assert rc == 1, out
    assert cardctl.INS_SIGN_ARBITRARY not in applet.ins_sent
    assert "applet 0.2" in out and "ENG-615" in out and "Sweep the balance" in out, out
    assert "stranded" not in out, out


def test_selftest_fails_every_build_below_0_3_blocked_or_not():
    """
    A 0.1 or 0.2 card whose PIN is set but not yet blocked is three wrong
    VERIFY_PINs away from an open gate (ENG-615): any reader in range can block
    the PIN and then spend without it. selftest used to pass such a card as
    healthy, because its only version check ran once the PIN was already
    blocked, after the attacker's three APDUs. The rollout says every card
    below 0.3 is swept and reinstalled, so selftest must fail each of them.
    """
    for version in ((0, 1), (0, 2)):
        for pin_state in (0, 1):
            applet = FakeApplet(version=version, pin_state=pin_state, gate="0.2")
            flags = ("--pin", "1234") if pin_state == 1 else ()
            rc, out = run_selftest(applet, *flags)
            label = f"applet {version[0]}.{version[1]}, pin_state {pin_state}"
            assert rc == 1, f"{label}\n{out}"
            assert "FAIL  SELECT applet" in out, f"{label}\n{out}"
            assert f"applet {version[0]}.{version[1]} is an ENG-615 build" in out, f"{label}\n{out}"
            assert "checks passed" not in out, f"{label}\n{out}"


def test_selftest_fails_every_0_3_card_blocked_or_not():
    """
    `main` tracked a 0.3 CAP (958a8baa…) that still wrote a slot's status byte
    before its data (ENG-620, D14), and nothing on an installed card tells it
    apart from a 0.3 build with the fix: SELECT's version is all the card
    reports about its build. selftest passed every 0.3 card as healthy. It
    must fail each one, with or without a PIN, and name the fix: reinstall the
    0.4 CAP, sweeping first unless the PIN is blocked. A blocked 0.3 card cannot
    spend (its balance is stranded), so it is never told to sweep outright.
    """
    for pin_state in (0, 1, 2):
        applet = FakeApplet(version=(0, 3), pin_state=pin_state)
        flags = ("--pin", "1234") if pin_state == 1 else ()
        rc, out = run_selftest(applet, *flags)
        label = f"applet 0.3, pin_state {pin_state}"
        assert rc == 1, f"{label}\n{out}"
        assert "FAIL  SELECT applet" in out, f"{label}\n{out}"
        assert "applet 0.3 may carry ENG-620" in out, f"{label}\n{out}"
        assert "reinstall the tracked CAP" in out, f"{label}\n{out}"
        assert "unless its PIN is blocked" in out, f"{label}\n{out}"
        assert "checks passed" not in out, f"{label}\n{out}"
        if pin_state == 2:
            assert "sweep the balance, then" not in out.lower(), f"{label}\n{out}"
            assert "stranded" in out, f"{label}\n{out}"


def test_selftest_on_a_0_6_card_reports_the_puk_state_and_passes():
    applet = FakeApplet(version=(0, 6), pin_state=1, puk_state=1)
    rc, out = run_selftest(applet, "--pin", "1234")
    assert rc == 0, out
    assert "PASS  SELECT applet  — version 0.6" in out, out
    assert "PIN set, PUK set" in out, out
    assert "All 11 checks passed" in out, out


def test_selftest_on_a_blocked_0_6_card_names_unblock_pin_when_the_puk_is_set():
    """
    The whole point of D16 at the reader: a blocked card is no longer
    "stranded" when it has a PUK. selftest still fails it — nothing can sign
    until the PIN is replaced — but the detail names the recovery, not the
    loss, and sends nothing that would spend a PUK try.
    """
    applet = FakeApplet(version=(0, 6), pin_state=2, puk_state=1)
    rc, out = run_selftest(applet, "--pin", "1234")
    assert rc == 1, out
    assert "FAIL  PIN state" in out and "unblock-pin" in out and "(D16)" in out, out
    assert "stranded" not in out, out
    assert cardctl.INS_UNBLOCK_PIN not in applet.ins_sent, "selftest must not try to unblock"
    assert cardctl.INS_SIGN_ARBITRARY not in applet.ins_sent
    # Without a PUK, or with an exhausted one, the 0.6 card is as stranded
    # as a 0.5 card.
    for puk_state in (0, 2):
        applet = FakeApplet(version=(0, 6), pin_state=2, puk_state=puk_state)
        rc, out = run_selftest(applet)
        assert rc == 1, out
        assert "balance stranded (SECURITY-MODEL #14)" in out, (puk_state, out)
        assert "unblock-pin" not in out, (puk_state, out)


def test_select_verdict_passes_only_a_known_fixed_version():
    # 0.4 passes — it fixed ENG-620 and nothing since is a fix — but is told
    # it lacks CLEAR_PIN (0.5, D15) and UNBLOCK_PIN (0.6, D16), so a later
    # `clear-pin` or `unblock-pin` 6D00 is no surprise. 0.5 likewise lacks
    # the PUK.
    ok, detail = cardctl._select_verdict(bytes([0, 4]))
    assert ok is True and detail == "version 0.4 (no CLEAR_PIN or UNBLOCK_PIN; added in 0.5 and 0.6)", detail
    ok, detail = cardctl._select_verdict(bytes([0, 5]))
    assert ok is True and detail == "version 0.5 (no UNBLOCK_PIN; added in 0.6)", detail
    assert cardctl._select_verdict(bytes([0, 6])) == (True, "version 0.6")
    assert cardctl._select_verdict(bytes([1, 0]))[0] is True
    for version in (bytes([0, 1]), bytes([0, 2])):
        ok, detail = cardctl._select_verdict(version)
        assert ok is False and "ENG-615" in detail, detail
        assert "reinstall the tracked CAP" in detail, detail
    # 0.3 has the ENG-615 fix, but SELECT cannot tell the build main tracked
    # with the old slot write order (ENG-620) from one with the fix.
    ok, detail = cardctl._select_verdict(bytes([0, 3]))
    assert ok is False and "ENG-620" in detail and "reinstall the tracked CAP" in detail, detail
    # No version at all cannot be told apart from an ENG-615 or ENG-620 build.
    ok, detail = cardctl._select_verdict(b"")
    assert ok is False and "no applet version" in detail, detail


# ── error handling ───────────────────────────────────────────────────────────
def test_status_words_are_translated():
    assert "already spent" in cardctl.describe_sw(0x6985)
    assert "slot is empty" in cardctl.describe_sw(0x6A88)
    assert "PUK not set" in cardctl.describe_sw(0x6A82)
    assert "PUK already set" in cardctl.describe_sw(0x6A89)
    assert "PUK is exhausted" in cardctl.describe_sw(0x6983)
    assert "2 retries remaining" in cardctl.describe_sw(0x63C2)
    assert "0 retries remaining" in cardctl.describe_sw(0x63C0)
    # 63CX names the credential the command counts: the PIN everywhere but
    # UNBLOCK_PIN, where it is the PUK and the floor is terminal.
    assert "wrong PIN" in cardctl.describe_sw(0x63C2, "VERIFY_PIN")
    assert "2 retries remaining" in cardctl.describe_sw(0x63C2, "VERIFY_PIN")
    assert "wrong PIN" in cardctl.describe_sw(0x63C2, "CHANGE_PIN")
    assert "wrong PUK" in cardctl.describe_sw(0x63C9, "UNBLOCK_PIN")
    assert "9 PUK tries remaining" in cardctl.describe_sw(0x63C9, "UNBLOCK_PIN")
    assert "exhausted for good" in cardctl.describe_sw(0x63C0, "UNBLOCK_PIN")
    assert "wrong PIN" not in cardctl.describe_sw(0x63C9, "UNBLOCK_PIN")
    assert cardctl.describe_sw(0x6983, "UNBLOCK_PIN").startswith("PUK exhausted")
    assert cardctl.describe_sw(0x6983, "VERIFY_PIN").startswith("PIN blocked")
    # A write to a card locked by LOCK_CARD (spec/APDU.md, LOAD_PROOF and the
    # error summary). It used to read "unknown status word".
    assert "LOCK_CARD" in cardctl.describe_sw(0x6986)
    assert "blocked" in cardctl.describe_sw(0x6982)


def test_non_9000_raises_carderror_with_context():
    card = make_card([(b"", 0x6985)])
    try:
        card.spend_proof(0, bytes(32))
    except cardctl.CardError as exc:
        assert exc.sw == 0x6985
        assert "SPEND_PROOF slot 0" in str(exc)
    else:
        raise AssertionError("expected CardError")



# ── APDU timing (--timing) ───────────────────────────────────────────────────
def test_transmit_records_one_timing_row_per_apdu_named_by_context():
    cardctl.TIMINGS.clear()
    card = make_card([(b"\x00\x04", 0x9000), (b"\x00" * 8, 0x9000)])
    card.select()
    card.get_info()
    contexts = [ctx for ctx, _ in cardctl.TIMINGS]
    assert contexts == ["SELECT", "GET_INFO"], contexts
    assert all(ms >= 0.0 for _, ms in cardctl.TIMINGS)


def test_a_failed_apdu_is_still_timed():
    # The row lands before the status word is judged: a 6982 that took 700 ms
    # is exactly the kind of number a timing run exists to show.
    cardctl.TIMINGS.clear()
    card = make_card([(b"", 0x6982)])
    try:
        card.send(cardctl.INS_SIGN_ARBITRARY, data=b"\x00" * 32, le=0x40, context="SIGN_ARBITRARY")
    except cardctl.CardError:
        pass
    assert [ctx for ctx, _ in cardctl.TIMINGS] == ["SIGN_ARBITRARY"]


def test_timing_flag_prints_each_apdu_only_when_enabled():
    cardctl.TIMINGS.clear()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        make_card([(b"\x00\x04", 0x9000)]).select()
    assert "⏱" not in err.getvalue()

    cardctl.TIMING_ENABLED = True
    try:
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            make_card([(b"\x00\x04", 0x9000)]).select()
    finally:
        cardctl.TIMING_ENABLED = False
    assert "⏱ SELECT" in err.getvalue(), err.getvalue()
    assert err.getvalue().rstrip().endswith("ms")


def test_summarize_timings_groups_by_command_with_median_not_mean():
    rows = [("SELECT", 60.0),
            ("SPEND_PROOF", 700.0), ("SPEND_PROOF", 740.0), ("SPEND_PROOF", 3000.0)]
    text = cardctl.summarize_timings(rows)
    lines = text.splitlines()
    assert lines[0].split() == ["command", "n", "min", "median", "max", "total"]
    spend = next(l for l in lines if l.startswith("SPEND_PROOF")).split()
    # n=3, min 700, median 740 (a mean would say 1480), max 3000, total 4440
    assert spend[1:] == ["3", "700.0", "740.0", "3000.0", "4440.0"], spend
    assert lines[-1].startswith("4 APDU(s), 4500.0 ms")


def test_summarize_timings_with_no_rows_does_not_crash():
    assert cardctl.summarize_timings([]) == "no APDUs sent"


def test_timing_flag_is_global_and_off_by_default():
    parser = cardctl.build_parser()
    assert parser.parse_args(["info"]).timing is False
    assert parser.parse_args(["--timing", "selftest", "--rounds", "5"]).timing is True
    assert parser.parse_args(["-t", "spend", "0"]).timing is True

if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and isinstance(fn, types.FunctionType):
            try:
                fn()
                print(f"PASS  {name}")
            # Not just AssertionError. cardctl reports operator errors by raising
            # SystemExit, and a parser/command mismatch surfaces as AttributeError
            # — both were verified to escape an AssertionError-only handler, kill
            # the run with no summary line, and silently skip every later test.
            # A detected regression must read as a FAIL, not as a crash.
            # SystemExit is spelled out because it derives from BaseException, not
            # Exception; everything else a test can raise is already covered.
            except (SystemExit, Exception) as exc:
                failures += 1
                print(f"FAIL  {name}: {type(exc).__name__}: {exc}")
                if not isinstance(exc, (AssertionError, SystemExit)):
                    traceback.print_exc()
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)

