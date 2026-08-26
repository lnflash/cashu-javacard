"""
APDU encoding tests for cardctl.

These assert the exact bytes cardctl puts on the wire against spec/APDU.md.
Worth having because the alternative is discovering an off-by-one in P1 or a
missing Le byte while hunched over a card reader, where every iteration costs a
re-tap and the failure looks identical to a hardware problem.

No reader and no card required — the PC/SC connection is faked.

Run:  python3 -m pytest test_apdu.py -q     (or: python3 test_apdu.py)
"""

import sys
import types

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
    cases = [
        ("get_info", (), "B0010000 00"),
        ("get_pubkey", (), "B0100000 21"),
        ("get_balance", (), "B0110000 04"),
        ("get_proof_count", (), "B0120000 01"),
        ("get_slot_status", (), "B0140000 20"),
    ]
    for method, args, expected in cases:
        # Give each call a response long enough not to trip length checks.
        card = make_card([(b"\x00" * 40, 0x9000)])
        getattr(card, method)(*args)
        assert card.connection.last == bytes.fromhex(expected.replace(" ", "")), \
            f"{method}: {card.connection.last.hex()} != {expected}"


def test_get_proof_puts_slot_in_p1_and_asks_for_78_bytes():
    card = make_card([(b"\x01" + b"\x00" * 77, 0x9000)])
    card.get_proof(5)
    assert card.connection.last == bytes.fromhex("B0130500" + "4E")


def test_get_proof_parses_the_slot_layout():
    body = (
        b"\x01"                       # status: unspent
        + b"0059534c"[:8].ljust(8, b"0")  # keyset id (ascii bytes)
        + (1234).to_bytes(4, "big")   # amount
        + bytes(range(32))            # secret
        + b"\x02" + bytes(range(32))  # C
    )
    assert len(body) == 78
    card = make_card([(body, 0x9000)])
    p = card.get_proof(0)
    assert p["status"] == "unspent"
    assert p["amount"] == 1234
    assert p["secret"] == bytes(range(32))
    assert p["c"][0] == 0x02 and len(p["c"]) == 33


def test_get_info_decodes_capabilities_and_pin_state():
    # v0.1, 32 slots, 3 unspent, 1 spent, 28 empty, caps=0x03, pin=set
    card = make_card([(bytes([0, 1, 32, 3, 1, 28, 0x03, 1]), 0x9000)])
    i = card.get_info()
    assert i["version"] == "0.1" and i["max_slots"] == 32
    assert i["unspent"] == 3 and i["spent"] == 1 and i["empty"] == 28
    assert i["secp256k1_native"] and i["schnorr"]
    assert i["pin_state"] == "set"


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
    slot = card.load_proof(b"0059534c", 5000, bytes(range(32)), b"\x02" + bytes(range(32)))
    assert slot == 7
    sent = card.connection.last
    assert sent[:4] == bytes.fromhex("B0300000")
    assert sent[4] == 0x4D, f"Lc should be 77, got {sent[4]}"
    payload = sent[5:5 + 77]
    assert payload[:8] == b"0059534c"
    assert int.from_bytes(payload[8:12], "big") == 5000
    assert sent[-1] == 0x01  # Le


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


def test_lock_card_sends_the_confirmation_byte_in_p2():
    card = make_card()
    card.lock_card()
    assert card.connection.last == bytes.fromhex("B05000DE")


# ── error handling ───────────────────────────────────────────────────────────
def test_status_words_are_translated():
    assert "already spent" in cardctl.describe_sw(0x6985)
    assert "slot is empty" in cardctl.describe_sw(0x6A88)
    assert "2 retries remaining" in cardctl.describe_sw(0x63C2)
    assert "0 retries remaining" in cardctl.describe_sw(0x63C0)


def test_non_9000_raises_carderror_with_context():
    card = make_card([(b"", 0x6985)])
    try:
        card.spend_proof(0, bytes(32))
    except cardctl.CardError as exc:
        assert exc.sw == 0x6985
        assert "SPEND_PROOF slot 0" in str(exc)
    else:
        raise AssertionError("expected CardError")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and isinstance(fn, types.FunctionType):
            try:
                fn()
                print(f"PASS  {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL  {name}: {exc}")
    print(f"\n{'all tests passed' if not failures else f'{failures} FAILED'}")
    sys.exit(1 if failures else 0)
