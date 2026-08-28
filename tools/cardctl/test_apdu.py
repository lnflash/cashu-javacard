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
import sys
import traceback
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
