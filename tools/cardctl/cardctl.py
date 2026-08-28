#!/usr/bin/env python3
"""
cardctl — host-side PC/SC driver for the Cashu JavaCard applet.

Speaks the full command set in spec/APDU.md over either interface: a contact
reader (ACR39U and friends) or a contactless one (ACR122U). PC/SC hides the
difference, so the same commands work for both — which matters, because CAP
loading over contactless is the flaky path and you will want to know quickly
whether a failure is the card or the interface.

The command that earns this tool its keep is `selftest`: it selects the applet,
reads the card's public key, asks the card to sign a message, and verifies that
signature against BIP-340. Everything up to now has been proven only in
jCardSim, which cannot surface EEPROM exhaustion, ECDH output framing, or a
card whose getS returns short. `selftest` is the first evidence from silicon.

    python3 cardctl.py readers
    python3 cardctl.py selftest
    python3 cardctl.py info
    python3 cardctl.py spend 0 --message <64-hex>

Requires: pip install -r requirements.txt   (pyscard)
"""

import argparse
import binascii
import json
import hashlib
import os
import secrets
import sys
from typing import List, Optional, Tuple

import bip340

# ── Applet identity ───────────────────────────────────────────────────────────
# The 7-byte PACKAGE AID. SELECT does prefix matching, so this also selects the
# 8-byte applet AID (…02 01). We try the 8-byte form as a fallback for cards or
# readers that decline partial matches.
PACKAGE_AID = bytes.fromhex("D276000085010200")[:7]
APPLET_AID = bytes.fromhex("D276000085010201")

CLA = 0xB0

INS_GET_INFO = 0x01
INS_GET_PUBKEY = 0x10
INS_GET_BALANCE = 0x11
INS_GET_PROOF_COUNT = 0x12
INS_GET_PROOF = 0x13
INS_GET_SLOT_STATUS = 0x14
INS_SPEND_PROOF = 0x20
INS_SIGN_ARBITRARY = 0x21
INS_LOAD_PROOF = 0x30
INS_CLEAR_SPENT = 0x31
INS_VERIFY_PIN = 0x40
INS_SET_PIN = 0x41
INS_CHANGE_PIN = 0x42
INS_LOCK_CARD = 0x50

LOCK_CONFIRM_BYTE = 0xDE

PROOF_SIZE = 78
STATUS_NAMES = {0x00: "empty", 0x01: "unspent", 0x02: "spent"}

# The card's amount field is a 4-byte unsigned integer (spec/APDU.md,
# LOAD_PROOF). Anything at or above this bound makes `amount.to_bytes(4, "big")`
# raise a bare OverflowError — and on the file path that happens mid-load, after
# earlier proofs are already committed. Bound it before the first write.
MAX_SLOT_AMOUNT = 2 ** 32

SW_MEANINGS = {
    0x9000: "success",
    0x6700: "wrong length",
    0x6982: "security condition not satisfied (PIN required but not verified)",
    0x6983: "PIN blocked — retries exhausted",
    0x6984: "PIN not set",
    0x6985: "conditions not satisfied (already spent / PIN already set / card locked)",
    0x6A83: "slot index out of range",
    0x6A84: "no space — all slots occupied",
    0x6A88: "slot is empty",
    0x6D00: "instruction not supported",
    0x6E00: "class not supported",
    0x6F00: "signing failed (hardware error)",
}


def describe_sw(sw: int) -> str:
    if sw in SW_MEANINGS:
        return SW_MEANINGS[sw]
    if (sw & 0xFFF0) == 0x63C0:
        return f"wrong PIN — {sw & 0x0F} retries remaining"
    return "unknown status word"


class CardError(Exception):
    def __init__(self, sw: int, context: str = ""):
        self.sw = sw
        where = f" during {context}" if context else ""
        super().__init__(f"card returned {sw:04X}{where}: {describe_sw(sw)}")


def _hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()


def validate_slot_amount(value, where: str = "") -> int:
    """
    A Cashu denomination that the card's 4-byte field can hold.

    Two rules, both of which cost nothing here and cost a burned slot anywhere
    else:

    * **A positive power of two.** A mint keyset has no key for amount 3, so a
      proof carrying one is rejected on redemption — after the slot is gone.
      This is the same rule cashu-client's `requireAmount` enforces on the other
      side of the card file; a value it refuses is a value this tool must never
      write, or the two halves disagree about what a valid proof is.
    * **Below `2**32`.** The APDU field is a 4-byte unsigned integer, so
      anything larger makes `amount.to_bytes(4, "big")` raise a bare
      OverflowError part-way through a load, after earlier proofs have already
      committed.

    Lives here rather than in the file parser because both entry points to
    LOAD_PROOF — `cardctl load` and `cardctl load-file` — must agree on what a
    valid amount is. They did not, and `load --amount 5` wrote a proof that the
    file format then refused to carry back off the card.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        # Reported before the range check so a string "8" out of an untyped
        # reader bridge does not render as `got 8` — a message that looks like a
        # valid value and hides the type error.
        raise SystemExit(
            f"{where}amount must be a positive integer, got "
            f"{type(value).__name__} {value!r}"
        )
    if not 0 < value < MAX_SLOT_AMOUNT:
        raise SystemExit(
            f"{where}amount must be a positive integer below 2**32 "
            f"(the card's amount field is a 4-byte uint), got {value!r}"
        )
    if value & (value - 1) != 0:
        raise SystemExit(
            f"{where}amount must be a positive power of two — a mint keyset has "
            f"no key for other denominations, so the proof is rejected on "
            f"redemption after the slot is already burned. Got {value!r}."
        )
    return value


# ── PC/SC transport ───────────────────────────────────────────────────────────
def _load_pyscard():
    try:
        from smartcard.System import readers  # noqa
        from smartcard.util import toHexString  # noqa
        return readers
    except ImportError:
        sys.exit(
            "pyscard is not installed.\n"
            "  pip install -r requirements.txt\n"
            "On macOS PC/SC ships with the OS — do NOT install pcsc-lite.\n"
            "On Debian/Ubuntu you also need: sudo apt install pcscd libpcsclite-dev"
        )


class Card:
    """A connected card with the Cashu applet selected."""

    def __init__(self, reader_index: int = 0, verbose: bool = False):
        readers_fn = _load_pyscard()
        available = readers_fn()
        if not available:
            sys.exit(
                "No PC/SC readers found.\n"
                "  - Is the reader plugged in?\n"
                "  - Linux: is pcscd running? (sudo systemctl start pcscd)\n"
                "  - macOS: the daemon is built in; try replugging the reader."
            )
        if reader_index >= len(available):
            sys.exit(f"Reader index {reader_index} out of range ({len(available)} found)")
        self.reader = available[reader_index]
        self.verbose = verbose
        try:
            self.connection = self.reader.createConnection()
            self.connection.connect()
        except Exception as exc:  # noqa: BLE001 — surface the driver's own words
            sys.exit(f"Could not connect to a card on {self.reader}: {exc}\nIs a card on the reader?")

    # ── raw APDU ──────────────────────────────────────────────────────────────
    def transmit(self, apdu: bytes, context: str = "") -> bytes:
        if self.verbose:
            print(f"  > {_hex(apdu)}", file=sys.stderr)
        data, sw1, sw2 = self.connection.transmit(list(apdu))
        sw = (sw1 << 8) | sw2
        body = bytes(data)
        if self.verbose:
            print(f"  < {_hex(body)} {sw:04X}", file=sys.stderr)
        if sw != 0x9000:
            raise CardError(sw, context)
        return body

    def send(self, ins: int, p1: int = 0, p2: int = 0,
             data: bytes = b"", le: Optional[int] = None, context: str = "") -> bytes:
        apdu = bytes([CLA, ins, p1, p2])
        if data:
            apdu += bytes([len(data)]) + data
        if le is not None:
            apdu += bytes([le])
        return self.transmit(apdu, context or f"INS {ins:02X}")

    # ── selection ─────────────────────────────────────────────────────────────
    def select(self) -> bytes:
        """SELECT by AID. Returns the 2-byte applet version."""
        for aid in (PACKAGE_AID, APPLET_AID):
            apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
            try:
                return self.transmit(apdu, "SELECT")
            except CardError as exc:
                last = exc
        raise SystemExit(
            f"SELECT failed: {last}\n"
            "The applet is probably not installed on this card. Load it with:\n"
            "  gp -install applet/target/cashu-javacard-0.1.0.cap"
        )

    # ── read commands ─────────────────────────────────────────────────────────
    def get_info(self) -> dict:
        b = self.send(INS_GET_INFO, le=0x00, context="GET_INFO")
        if len(b) < 8:
            raise SystemExit(f"GET_INFO returned {len(b)} bytes, expected 8: {_hex(b)}")
        caps = b[6]
        return {
            "version": f"{b[0]}.{b[1]}",
            "max_slots": b[2],
            "unspent": b[3],
            "spent": b[4],
            "empty": b[5],
            "caps_raw": caps,
            "secp256k1_native": bool(caps & 0x01),
            "schnorr": bool(caps & 0x02),
            "pin_state": {0: "unset", 1: "set", 2: "locked"}.get(b[7], f"unknown({b[7]})"),
        }

    def get_pubkey(self) -> bytes:
        return self.send(INS_GET_PUBKEY, le=0x21, context="GET_PUBKEY")

    def get_balance(self) -> int:
        return int.from_bytes(self.send(INS_GET_BALANCE, le=0x04, context="GET_BALANCE"), "big")

    def get_proof_count(self) -> int:
        return self.send(INS_GET_PROOF_COUNT, le=0x01, context="GET_PROOF_COUNT")[0]

    def get_slot_status(self) -> bytes:
        return self.send(INS_GET_SLOT_STATUS, le=0x20, context="GET_SLOT_STATUS")

    def get_proof(self, slot: int) -> dict:
        b = self.send(INS_GET_PROOF, p1=slot, le=PROOF_SIZE, context=f"GET_PROOF slot {slot}")
        return {
            "slot": slot,
            "status": STATUS_NAMES.get(b[0], f"unknown({b[0]})"),
            # Raw bytes -> hex gives the full 16-char NUT-02 id. Decoding these
            # as ASCII would yield only 8 hex chars: half an id, matching no
            # keyset at the mint.
            "keyset_id": b[1:9].hex(),
            "amount": int.from_bytes(b[9:13], "big"),
            # The 32 bytes are the P2PK *nonce*, not the secret string.
            "nonce": b[13:45],
            "c": b[45:78],
        }

    # ── spend commands ────────────────────────────────────────────────────────
    def spend_proof(self, slot: int, message: bytes) -> bytes:
        if len(message) != 32:
            raise SystemExit(f"SPEND_PROOF message must be 32 bytes, got {len(message)}")
        return self.send(INS_SPEND_PROOF, p1=slot, data=message, le=0x40,
                         context=f"SPEND_PROOF slot {slot}")

    def sign(self, message: bytes) -> bytes:
        if len(message) != 32:
            raise SystemExit(f"SIGN_ARBITRARY message must be 32 bytes, got {len(message)}")
        return self.send(INS_SIGN_ARBITRARY, data=message, le=0x40, context="SIGN_ARBITRARY")

    # ── write commands ────────────────────────────────────────────────────────
    def load_proof(self, keyset_id: bytes, amount: int, nonce: bytes, c: bytes) -> int:
        if len(keyset_id) != 8:
            raise SystemExit(f"keyset_id must be 8 raw bytes, got {len(keyset_id)}")
        # Every caller goes through here, so this is the one place that cannot be
        # bypassed. `cardctl load --amount 4294967296` used to reach
        # `amount.to_bytes(4, "big")` and die on a bare OverflowError traceback;
        # `--amount 0` used to burn one of 32 scarce slots on a worthless proof.
        validate_slot_amount(amount)
        if len(nonce) != 32:
            raise SystemExit(f"nonce must be 32 bytes, got {len(nonce)}")
        if len(c) != 33:
            raise SystemExit(f"C must be 33 bytes, got {len(c)}")
        payload = keyset_id + amount.to_bytes(4, "big") + nonce + c
        return self.send(INS_LOAD_PROOF, data=payload, le=0x01, context="LOAD_PROOF")[0]

    def clear_spent(self) -> int:
        return self.send(INS_CLEAR_SPENT, le=0x01, context="CLEAR_SPENT")[0]

    # ── auth ──────────────────────────────────────────────────────────────────
    def verify_pin(self, pin: bytes) -> None:
        self.send(INS_VERIFY_PIN, data=pin, context="VERIFY_PIN")

    def set_pin(self, pin: bytes) -> None:
        self.send(INS_SET_PIN, data=pin, context="SET_PIN")

    def change_pin(self, old: bytes, new: bytes) -> None:
        self.send(INS_CHANGE_PIN, data=bytes([len(old)]) + old + new, context="CHANGE_PIN")

    def lock_card(self) -> None:
        self.transmit(bytes([CLA, INS_LOCK_CARD, 0x00, LOCK_CONFIRM_BYTE]), "LOCK_CARD")


# ── helpers ───────────────────────────────────────────────────────────────────
def parse_hex(value: str, expected_len: Optional[int] = None, what: str = "value") -> bytes:
    try:
        b = bytes.fromhex(value.removeprefix("0x"))
    except ValueError:
        raise SystemExit(f"{what} is not valid hex: {value!r}")
    if expected_len is not None and len(b) != expected_len:
        raise SystemExit(f"{what} must be {expected_len} bytes ({expected_len*2} hex chars), got {len(b)}")
    return b


def connect(args) -> Card:
    card = Card(reader_index=args.reader, verbose=args.verbose)
    card.select()
    return card


def check_signature(pubkey: bytes, message: bytes, sig: bytes) -> bool:
    return bip340.verify(bip340.x_only(pubkey), message, sig)


# ── commands ──────────────────────────────────────────────────────────────────
def cmd_readers(args) -> int:
    readers_fn = _load_pyscard()
    found = readers_fn()
    if not found:
        print("No PC/SC readers found.")
        return 1
    for i, r in enumerate(found):
        print(f"[{i}] {r}")
    return 0


def cmd_info(args) -> int:
    card = connect(args)
    i = card.get_info()
    print(f"applet version   : {i['version']}")
    print(f"slots            : {i['max_slots']} total — "
          f"{i['unspent']} unspent, {i['spent']} spent, {i['empty']} empty")
    print(f"capabilities     : 0x{i['caps_raw']:02X} "
          f"(secp256k1 native={i['secp256k1_native']}, schnorr={i['schnorr']})")
    print(f"PIN              : {i['pin_state']}")
    print(f"balance          : {card.get_balance()}")
    return 0


def cmd_pubkey(args) -> int:
    card = connect(args)
    pk = card.get_pubkey()
    print(_hex(pk))
    if args.verbose:
        print(f"x-only: {_hex(bip340.x_only(pk))}", file=sys.stderr)
    return 0


def cmd_balance(args) -> int:
    print(connect(args).get_balance())
    return 0


def cmd_slots(args) -> int:
    card = connect(args)
    status = card.get_slot_status()
    print(f"{len(status)} slots ({card.get_proof_count()} non-empty)")
    for i, s in enumerate(status):
        if s != 0x00 or args.all:
            print(f"  [{i:2}] {STATUS_NAMES.get(s, f'unknown({s})')}")
    return 0


def cmd_proof(args) -> int:
    p = connect(args).get_proof(args.slot)
    print(f"slot      : {p['slot']}")
    print(f"status    : {p['status']}")
    print(f"keyset_id : {p['keyset_id']}")
    print(f"amount    : {p['amount']}")
    print(f"nonce     : {_hex(p['nonce'])}")
    print(f"C         : {_hex(p['c'])}")
    return 0


def cmd_sign(args) -> int:
    card = connect(args)
    msg = parse_hex(args.message, 32, "message") if args.message else secrets.token_bytes(32)
    if not args.message:
        print(f"message   : {_hex(msg)}  (random)")
    sig = card.sign(msg)
    print(f"signature : {_hex(sig)}")
    ok = check_signature(card.get_pubkey(), msg, sig)
    print(f"BIP-340   : {'VALID ✅' if ok else 'INVALID ❌'}")
    return 0 if ok else 1


def cmd_spend(args) -> int:
    card = connect(args)
    msg = parse_hex(args.message, 32, "message") if args.message else secrets.token_bytes(32)
    if not args.message:
        print(f"message   : {_hex(msg)}  (random)")
    before = card.get_proof(args.slot)
    print(f"slot {args.slot} before : {before['status']}, amount {before['amount']}")
    sig = card.spend_proof(args.slot, msg)
    print(f"signature : {_hex(sig)}")
    ok = check_signature(card.get_pubkey(), msg, sig)
    print(f"BIP-340   : {'VALID ✅' if ok else 'INVALID ❌'}")
    after = card.get_proof(args.slot)
    print(f"slot {args.slot} after  : {after['status']}")
    if after["status"] != "spent":
        print("WARNING: slot was not marked spent — single-spend enforcement failed", file=sys.stderr)
        return 1
    return 0 if ok else 1


def parse_keyset_id(value: str, what: str = "--keyset") -> bytes:
    """
    A NUT-02 keyset id is 16 hex characters, which is 8 bytes raw.

    Earlier versions accepted an 8-character value and ASCII-encoded it. That
    silently stored half an id — the resulting proof matches no keyset at the
    mint and the funds are stranded on the card. Reject it loudly instead.

    The truncation message only fires for a value that is plausibly half an id,
    i.e. actually hex. Anything else falls through to parse_hex's "not valid
    hex" error rather than sending the operator hunting for a truncation that
    never happened.

    `what` names the thing the operator has to go and fix. The same id arrives
    from two places — the `--keyset` flag and a card file's `keysetId` field —
    and pointing at a CLI flag that the failing command does not even have
    sends them looking in the wrong file.
    """
    v = value.strip().lower()
    if len(v) == 8 and all(c in "0123456789abcdef" for c in v):
        raise SystemExit(
            f"{what} {value!r} is 8 hex chars, but a NUT-02 keyset id is 16 "
            f"(e.g. 0059534ce0bfa19a). Eight characters is half an id; a proof "
            f"loaded with it cannot be spent. Pass the full id."
        )
    raw = parse_hex(v, 8, what.lstrip("-"))
    # NUT-02 v0 ids begin with a 0x00 version byte. cashu-client runs the same
    # check (`requireKeysetV0`) on both the card path and the file path, so an id
    # this tool accepts and writes but the other half refuses is a proof that
    # dies at the boundary — after the slot is spent.
    if raw[0] != 0x00:
        raise SystemExit(
            f"{what} {value!r} must be a NUT-02 v0 keyset id (00 version byte), "
            f"got 0x{raw[0]:02x}"
        )
    return raw


def cmd_load(args) -> int:
    # Parse every argument before touching the reader. VERIFY_PIN decrements the
    # card's retry counter, so running it ahead of validation means a typo'd
    # --keyset costs a PIN attempt on a command that could never have succeeded.
    # Pure argument validation must never require a card tap.
    keyset = parse_keyset_id(args.keyset)
    validate_slot_amount(args.amount)
    nonce = parse_hex(args.nonce, 32, "nonce") if args.nonce else secrets.token_bytes(32)
    c = parse_hex(args.c, 33, "C") if args.c else b"\x02" + secrets.token_bytes(32)
    card = connect(args)
    if args.pin:
        card.verify_pin(args.pin.encode())
    slot = card.load_proof(keyset, args.amount, nonce, c)
    print(f"loaded into slot {slot}")
    if not args.nonce:
        print(f"nonce  : {_hex(nonce)}")
    if not args.c:
        print(f"C      : {_hex(c)}  (placeholder, not a real mint signature)")
    return 0


# ── card file (interchange with cashu-client) ─────────────────────────────────
#
# The mint protocol lives in TypeScript (lnflash/cashu-client) and this driver
# is Python, so proofs cross the boundary as a file. The schema is defined once,
# in cashu-client's `src/cardFile.ts`; this is the other half of it.
#
# The field names are the card's own vocabulary — `nonce`, not `secret`, and a
# 16-hex-char `keysetId`. A file that says `secret` was written against a wrong
# model: a NUT-10 P2PK secret is ~150 bytes of JSON and cannot live in a slot.
#
# The schema is published in spec/CARD-FILE.md and test_card_file.py asserts
# this parser against it, the same way test_spec_consistency.py asserts the APDU
# encodings against spec/APDU.md.

CARD_FILE_VERSION = 1

# The published field lists, mirroring cashu-client's SLOT_FIELDS / FILE_FIELDS.
# Kept as the exact names in spec/CARD-FILE.md's tables — test_card_file.py
# parses the document and asserts these against it, so a rename fails in CI.
SLOT_FIELDS = ("keysetId", "amount", "nonce", "C", "spent")
FILE_FIELDS = ("version", "mint", "unit", "cardPubkey", "slots", "note")


def _reject_unknown_fields(raw: dict, known, where: str) -> None:
    """
    Refuse a field this version does not know about.

    The format's whole claim is that a field which drifts fails at the boundary.
    Silently ignoring an unrecognised key is that drift: a future writer adds
    one, forgets to bump `version`, and this side discards it without a word —
    the failure then surfaces at the mint, or as money that quietly went
    nowhere. `version` exists precisely so an additive change announces itself.

    Strict on both sides on purpose: cashu-client's `rejectUnknownFields` does
    exactly this, and a format whose two halves disagree about forward
    compatibility is not one format.
    """
    extra = [k for k in raw if k not in known]
    if extra:
        raise SystemExit(
            f"{where}unknown field(s): {', '.join(sorted(extra))} — bump the "
            f"card file version rather than adding fields silently"
        )


def _slot_from_json(entry, index: int) -> dict:
    """Validate one slot from a card file. Mirrors parseCardSlot in cashu-client."""
    where = f"slot {index}: "
    if not isinstance(entry, dict):
        raise SystemExit(f"{where}expected an object, got {type(entry).__name__}")

    # A file that spells this `secret` was written against the wrong mental
    # model. Say so, rather than reporting it as an unknown field.
    if "nonce" not in entry and "secret" in entry:
        raise SystemExit(
            f'{where}has "secret" but no "nonce" — the card stores the 32-byte '
            f"P2PK nonce, not the secret string (~150 bytes of JSON). See NUT-XX."
        )
    _reject_unknown_fields(entry, SLOT_FIELDS, where)

    amount = validate_slot_amount(entry.get("amount"), where)

    keyset = entry.get("keysetId")
    if not isinstance(keyset, str):
        raise SystemExit(f"{where}keysetId must be a hex string")
    c_hex = entry.get("C")
    if not isinstance(c_hex, str):
        raise SystemExit(f"{where}C must be a hex string")
    nonce_hex = entry.get("nonce")
    if not isinstance(nonce_hex, str):
        raise SystemExit(f"{where}nonce must be a hex string")

    # Required, never defaulted. A file that omits it is not a file of unspent
    # proofs, it is a file whose state is unknown — and guessing "unspent"
    # resurrects settled money as spendable balance. See spec/CARD-FILE.md.
    spent = entry.get("spent")
    if not isinstance(spent, bool):
        raise SystemExit(
            f"{where}spent must be a boolean — without it there is no way to "
            f"tell an unspent proof from one the card already burned, and "
            f"loading the file back would resurrect the spent ones. "
            f"Got {spent!r}."
        )

    try:
        keyset_id = parse_keyset_id(keyset, what="keysetId")
        nonce = parse_hex(nonce_hex, 32, f"{where}nonce")
        c = parse_hex(c_hex, 33, f"{where}C")
    except SystemExit as exc:
        raise SystemExit(f"{where}{exc}" if not str(exc).startswith(where) else str(exc))

    # Same guard cardPubkey gets. A C that is not a compressed point is an
    # unspendable proof, which is the whole reason this validator exists.
    if c[0] not in (0x02, 0x03):
        raise SystemExit(
            f"{where}C must be a compressed secp256k1 point (02/03 prefix), "
            f"got 0x{c[0]:02x}"
        )

    return {
        "keyset": keyset_id,
        "amount": amount,
        "nonce": nonce,
        "c": c,
        "spent": spent,
    }


def validate_card_doc(doc) -> dict:
    """
    Validate an already-decoded card file document.

    Split out of `read_card_file` so the *writer* can run it too: `cardctl dump`
    used to emit whatever it was handed — `dump --mint ""` exited 0, printed
    "wrote 2 slot(s)", and produced a file this same module refuses. The only
    off-card record of a card's proofs is not a thing to discover is unloadable
    later, possibly after the card has been re-provisioned. cashu-client's
    `serializeCardFile` round-trips through `parseCardFile` for the same reason.
    """
    if not isinstance(doc, dict):
        raise SystemExit("card file must be a JSON object")
    if doc.get("version") != CARD_FILE_VERSION:
        raise SystemExit(
            f"unsupported card file version {doc.get('version')!r}, "
            f"expected {CARD_FILE_VERSION}"
        )
    _reject_unknown_fields(doc, FILE_FIELDS, "card file: ")
    for field in ("mint", "unit"):
        if not isinstance(doc.get(field), str) or not doc[field]:
            raise SystemExit(f"card file {field} must be a non-empty string")
    pub = doc.get("cardPubkey")
    if not isinstance(pub, str):
        raise SystemExit("card file cardPubkey must be a hex string")
    card_pubkey = parse_hex(pub, 33, "cardPubkey")
    if card_pubkey[0] not in (0x02, 0x03):
        raise SystemExit(
            f"card file cardPubkey must be a compressed secp256k1 point "
            f"(02/03 prefix), got 0x{card_pubkey[0]:02x}"
        )
    slots = doc.get("slots")
    if not isinstance(slots, list):
        raise SystemExit("card file slots must be an array")

    return {
        "mint": doc["mint"],
        "unit": doc["unit"],
        "card_pubkey": card_pubkey,
        "slots": [_slot_from_json(e, i) for i, e in enumerate(slots)],
    }


def read_card_file(path: str) -> dict:
    """Parse and validate a card file. Refuses anything malformed."""
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except FileNotFoundError:
        raise SystemExit(f"no such card file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path} is not valid JSON: {exc}")

    return validate_card_doc(doc)


def _nonces_on_card(card) -> dict:
    """
    {nonce: (slot index, status byte)} for every occupied slot.

    This is what makes `load-file` re-runnable. LOAD_PROOF commits one proof at
    a time with no transaction around the file, so any mid-file failure leaves
    part of it on the card; without this, the obvious recovery — run it again —
    writes the already-loaded proofs a second time into fresh slots, inflating
    the on-card balance with duplicates the mint rejects on redemption.

    The status byte comes back with the index because "already there" and
    "already burned" are different answers. A file slot marked unspent whose
    nonce the card has already spent used to be reported as "already loaded,
    skipping" — which reads as "your proof is safely on the card" when the truth
    is the opposite, and the money is gone.
    """
    found = {}
    for index, status in enumerate(card.get_slot_status()):
        if status == 0x00:
            continue
        found.setdefault(card.get_proof(index)["nonce"], (index, status))
    return found


def cmd_load_file(args) -> int:
    """Load every proof in a card file, in order."""
    doc = read_card_file(args.path)

    card = connect(args)
    on_card = card.get_pubkey()
    if on_card != doc["card_pubkey"]:
        # Proofs are P2PK-locked to one card. Loading them onto a different card
        # writes money nothing can ever spend. Checked before the PIN and before
        # any write: there is nothing to undo yet.
        raise SystemExit(
            f"card file is for {_hex(doc['card_pubkey'])}\n"
            f"but this card is  {_hex(on_card)}\n"
            "These proofs are locked to a different card and could never be spent."
        )
    if args.pin:
        card.verify_pin(args.pin.encode())

    # A spent proof has already been burned by the card. LOAD_PROOF has no spent
    # bit, so writing one back returns it as unspent — balance the holder cannot
    # actually move. Dump keeps them because they are still owed at the mint;
    # load must not put them back on a card.
    settled = [s for s in doc["slots"] if s["spent"]]
    loadable = [s for s in doc["slots"] if not s["spent"]]

    # Pre-flight. Everything checkable before the first write happens before the
    # first write, because after it there is no rollback.
    already = _nonces_on_card(card)
    pending = [s for s in loadable if s["nonce"] not in already]
    empty = card.get_info()["empty"]
    if len(pending) > empty:
        raise SystemExit(
            f"card file needs {len(pending)} free slot(s) but this card has "
            f"{empty}. Nothing was written. Free space with `cardctl clear-spent` "
            f"or split the file across cards."
        )

    total = 0
    loaded = 0
    burned = 0
    for slot in doc["slots"]:
        if slot["spent"]:
            continue
        if slot["nonce"] in already:
            index, status = already[slot["nonce"]]
            if status == 0x02:
                # The file says unspent, the card says burned. Reporting this as
                # "already loaded" tells the operator their money is safely on
                # the card when it is already gone — and the summary counts
                # would fold it in with the genuinely-present proofs.
                burned += 1
                print(f"slot {index}: already SPENT on this card, skipping "
                      f"({slot['amount']} {doc['unit']} — the file is stale)")
            else:
                print(f"slot {index}: already loaded, skipping")
            continue
        index = card.load_proof(slot["keyset"], slot["amount"], slot["nonce"], slot["c"])
        already[slot["nonce"]] = (index, 0x01)
        loaded += 1
        total += slot["amount"]
        print(f"slot {index}: {slot['amount']} {doc['unit']}")

    skipped = len(loadable) - loaded - burned
    print(f"loaded {loaded} proof(s), {total} {doc['unit']} total"
          + (f"; {skipped} already on the card" if skipped else "")
          + (f"; {burned} already SPENT on the card" if burned else "")
          + (f"; {len(settled)} spent slot(s) not loaded" if settled else ""))
    return 0


def cmd_dump(args) -> int:
    """Write every non-empty slot to a card file for the mint side to redeem."""
    card = connect(args)
    pubkey = card.get_pubkey()
    statuses = card.get_slot_status()

    slots = []
    for index, status in enumerate(statuses):
        if status == 0x00:
            continue
        if args.unspent_only and status != 0x01:
            continue
        p = card.get_proof(index)
        slots.append({
            "keysetId": p["keyset_id"],
            "amount": p["amount"],
            "nonce": _hex(p["nonce"]),
            "C": _hex(p["c"]),
            # The bit that says whether this money still moves. Dropping it
            # keeps the proof and loses the state needed to act on it: the mint
            # side gets N indistinguishable proofs, and a reload resurrects the
            # spent ones as spendable. See spec/CARD-FILE.md.
            "spent": p["status"] == "spent",
        })

    doc = {
        "version": CARD_FILE_VERSION,
        "mint": args.mint,
        "unit": args.unit,
        "cardPubkey": _hex(pubkey),
        "slots": slots,
        "note": f"dumped by cardctl from {len(slots)} slot(s)",
    }

    # Never emit a document this module would refuse to read back. `dump --mint
    # ""` used to exit 0 and report success while producing an unloadable file —
    # and this file is the card's only off-card record, so the operator finds out
    # long after the card has moved on. The same round-trip cashu-client's
    # `serializeCardFile` does through `parseCardFile`.
    try:
        validate_card_doc(doc)
    except SystemExit as exc:
        # The failure can come from the arguments (fixable: pass a real --mint)
        # or from the card itself, if it was provisioned by an older cardctl that
        # allowed a denomination v1 cannot carry. Say which, and point at the
        # command that still gets the bytes out slot by slot.
        raise SystemExit(
            f"refusing to write a card file this tool could not read back: {exc}\n"
            f"Nothing was written. If the card holds a proof the v1 format "
            f"cannot represent, read it out with `cardctl proof <slot>`."
        )

    text = json.dumps(doc, indent=2)
    if args.out:
        # A card file is a bearer-money artifact and the only off-card record of
        # these proofs. Shell clobber semantics are the wrong default: dumping a
        # second card over card1.json would destroy the first card's only backup.
        if os.path.exists(args.out) and not args.force:
            raise SystemExit(
                f"{args.out} already exists; pass --force to overwrite. "
                f"(It may be the only copy of another card's proofs.)"
            )
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {len(slots)} slot(s) to {args.out}")
    else:
        print(text)
    return 0


def cmd_clear_spent(args) -> int:
    card = connect(args)
    if args.pin:
        card.verify_pin(args.pin.encode())
    print(f"freed {card.clear_spent()} slot(s)")
    return 0


def cmd_verify_pin(args) -> int:
    connect(args).verify_pin(args.pin.encode())
    print("PIN verified")
    return 0


def cmd_set_pin(args) -> int:
    connect(args).set_pin(args.pin.encode())
    print("PIN set")
    return 0


def cmd_change_pin(args) -> int:
    card = connect(args)
    card.verify_pin(args.old.encode())
    card.change_pin(args.old.encode(), args.new.encode())
    print("PIN changed")
    return 0


def cmd_lock(args) -> int:
    card = connect(args)
    if not args.yes:
        print("LOCK_CARD permanently and irreversibly disables all write operations.")
        if input("Type 'lock' to confirm: ").strip() != "lock":
            print("aborted")
            return 1
    if args.pin:
        card.verify_pin(args.pin.encode())
    card.lock_card()
    print("card locked (irreversible)")
    return 0


def cmd_apdu(args) -> int:
    card = Card(reader_index=args.reader, verbose=True)
    if not args.no_select:
        card.select()
    try:
        body = card.transmit(parse_hex(args.apdu, None, "apdu"), "raw APDU")
        print(_hex(body) if body else "(no data)")
        return 0
    except CardError as exc:
        print(exc, file=sys.stderr)
        return 1


def cmd_selftest(args) -> int:
    """
    The card-arrival test. Everything the applet claims, proven on real silicon.
    """
    results: List[Tuple[str, bool, str]] = []

    def record(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))
        print(f"{'PASS' if ok else 'FAIL'}  {name}{'  — ' + detail if detail else ''}")

    card = Card(reader_index=args.reader, verbose=args.verbose)
    print(f"reader: {card.reader}\n")

    version = card.select()
    record("SELECT applet", True, f"version {version[0]}.{version[1]}" if len(version) >= 2 else "")

    info = card.get_info()
    record("GET_INFO", True,
           f"v{info['version']}, {info['max_slots']} slots, PIN {info['pin_state']}")
    record("Schnorr capability advertised", info["schnorr"],
           f"caps=0x{info['caps_raw']:02X}")

    pk = card.get_pubkey()
    good_pk = len(pk) == 33 and pk[0] in (0x02, 0x03)
    record("GET_PUBKEY well-formed", good_pk, f"{_hex(pk)[:20]}… ({len(pk)} bytes)")

    card.get_balance()
    record("GET_BALANCE", True, str(card.get_balance()))

    status = card.get_slot_status()
    record("GET_SLOT_STATUS", len(status) == info["max_slots"],
           f"{len(status)} status bytes")

    # The whole point: does a signature off this card verify against BIP-340?
    all_sigs_ok = True
    for i in range(args.rounds):
        msg = secrets.token_bytes(32)
        sig = card.sign(msg)
        ok = check_signature(pk, msg, sig)
        all_sigs_ok &= ok
        record(f"SIGN_ARBITRARY + BIP-340 verify [{i + 1}/{args.rounds}]", ok,
               "" if ok else f"msg={_hex(msg)} sig={_hex(sig)}")

    # A fresh nonce per call is a BIP-340 requirement and a real security
    # property here: a nonce that is a pure function of (d, msg) leaks the key
    # to anyone who can fault-inject two signatures over the same message.
    if args.rounds >= 2:
        fixed = secrets.token_bytes(32)
        s1, s2 = card.sign(fixed), card.sign(fixed)
        record("fresh nonce across identical messages", s1[:32] != s2[:32],
               "R reused — aux randomness is not working" if s1[:32] == s2[:32] else "")

    failed = [n for n, ok, _ in results if not ok]
    print()
    if failed:
        print(f"{len(failed)} check(s) FAILED: {', '.join(failed)}")
        return 1
    print(f"All {len(results)} checks passed on physical hardware.")
    if not all_sigs_ok:
        return 1
    return 0


# ── argument parsing ──────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cardctl",
        description="PC/SC driver for the Cashu JavaCard applet (spec/APDU.md).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Start with:  cardctl readers   then   cardctl selftest",
    )
    p.add_argument("-r", "--reader", type=int, default=0, help="reader index (default 0)")
    p.add_argument("-v", "--verbose", action="store_true", help="log APDUs to stderr")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("readers", help="list PC/SC readers").set_defaults(func=cmd_readers)
    sub.add_parser("info", help="applet version, slot counts, capabilities, PIN state").set_defaults(func=cmd_info)
    sub.add_parser("pubkey", help="card's compressed secp256k1 public key").set_defaults(func=cmd_pubkey)
    sub.add_parser("balance", help="sum of unspent proof amounts").set_defaults(func=cmd_balance)

    s = sub.add_parser("slots", help="per-slot status")
    s.add_argument("--all", action="store_true", help="include empty slots")
    s.set_defaults(func=cmd_slots)

    s = sub.add_parser("proof", help="read a proof slot")
    s.add_argument("slot", type=int)
    s.set_defaults(func=cmd_proof)

    s = sub.add_parser("sign", help="SIGN_ARBITRARY and verify the signature")
    s.add_argument("--message", help="32-byte message as hex (random if omitted)")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("spend", help="SPEND_PROOF: mark spent, sign, verify")
    s.add_argument("slot", type=int)
    s.add_argument("--message", help="32-byte message as hex (random if omitted)")
    s.set_defaults(func=cmd_spend)

    s = sub.add_parser("load", help="LOAD_PROOF into the next free slot")
    s.add_argument("--keyset", required=True,
                   help="NUT-02 keyset id, 16 hex chars (e.g. 0059534ce0bfa19a)")
    s.add_argument("--amount", type=int, required=True)
    s.add_argument("--nonce", help="32-byte P2PK nonce as hex (random if omitted)")
    s.add_argument("--c", help="33-byte C point as hex (placeholder if omitted)")
    s.add_argument("--pin", help="verify this PIN first")
    s.set_defaults(func=cmd_load)

    s = sub.add_parser("load-file", help="LOAD_PROOF every proof in a card file")
    s.add_argument("path", help="card file written by cashu-client")
    s.add_argument("--pin", help="verify this PIN first")
    s.set_defaults(func=cmd_load_file)

    s = sub.add_parser("dump", help="write the card's slots out as a card file")
    s.add_argument("--mint", required=True, help="mint URL these proofs belong to")
    s.add_argument("--unit", default="sat", help="keyset unit (default: sat)")
    s.add_argument("--out", help="write here instead of stdout")
    s.add_argument("--force", action="store_true",
                   help="overwrite --out if it already exists")
    s.add_argument("--unspent-only", action="store_true",
                   help="skip spent slots (they are still readable, and still owed)")
    s.set_defaults(func=cmd_dump)

    s = sub.add_parser("clear-spent", help="free all spent slots")
    s.add_argument("--pin")
    s.set_defaults(func=cmd_clear_spent)

    s = sub.add_parser("verify-pin", help="verify the PIN for this session")
    s.add_argument("pin")
    s.set_defaults(func=cmd_verify_pin)

    s = sub.add_parser("set-pin", help="set the PIN (personalisation only, once)")
    s.add_argument("pin")
    s.set_defaults(func=cmd_set_pin)

    s = sub.add_parser("change-pin", help="change the PIN")
    s.add_argument("old")
    s.add_argument("new")
    s.set_defaults(func=cmd_change_pin)

    s = sub.add_parser("lock", help="permanently disable writes (IRREVERSIBLE)")
    s.add_argument("--pin")
    s.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    s.set_defaults(func=cmd_lock)

    s = sub.add_parser("apdu", help="send a raw APDU (hex)")
    s.add_argument("apdu")
    s.add_argument("--no-select", action="store_true", help="skip SELECT first")
    s.set_defaults(func=cmd_apdu)

    s = sub.add_parser("selftest", help="full hardware check incl. BIP-340 signature verification")
    s.add_argument("--rounds", type=int, default=3, help="signature rounds (default 3)")
    s.set_defaults(func=cmd_selftest)

    return p


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except CardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
