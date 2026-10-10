# APDU Command Reference

JavaCard Cashu Applet — AID: `D2 76 00 00 85 01 02`

All commands use `CLA = B0` unless noted. All multi-byte integers are big-endian.

---

## SELECT APPLICATION

Issued by reader before any other command. Standard ISO 7816-4 SELECT.

| Field | Value |
|-------|-------|
| CLA | 00 |
| INS | A4 |
| P1 | 04 |
| P2 | 00 |
| Lc | 07 |
| Data | `D2 76 00 00 85 01 02` |
| Response | 2-byte applet version (`MM mm`) + `90 00` |

The Data field above is the 7-byte **package** AID. ISO 7816-4 SELECT does
prefix matching, so it also selects the applet instance. Readers that decline
partial matches must retry with the full 8-byte **applet** AID
`D2 76 00 00 85 01 02 01` (Lc `08`) — that is exactly what `cardctl` does: the
7-byte form first, the 8-byte form as a fallback on any error. A reader that
sends neither selects nothing, and every subsequent command fails in a way that
looks like an uninstalled applet.

---

## Category 0x1x — Read (no authentication required)

### GET_INFO (0x01)

Returns applet version, capabilities, and slot statistics. Always available without authentication.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 01 |
| P1 | 00 |
| P2 | 00 |
| Le | 00 |

**Response (9 bytes):**

| Offset | Length | Description |
|--------|--------|-------------|
| 0 | 1 | Major version |
| 1 | 1 | Minor version |
| 2 | 1 | Max proof slots |
| 3 | 1 | Unspent proof count |
| 4 | 1 | Spent proof count |
| 5 | 1 | Empty slot count |
| 6 | 1 | Capabilities flags (see below) |
| 7 | 1 | PIN state (0=unset, 1=set, 2=locked — the PIN is blocked, tries exhausted; 1 returns to 0 only through `CLEAR_PIN`, and 2 returns to 1 only through `UNBLOCK_PIN`) |
| 8 | 1 | PUK state (0=unset, 1=set, 2=exhausted — ten wrong PUKs; terminal). Applet 0.6 and later; a 0.5 card answers 8 bytes |

Byte 8 was appended by applet 0.6 (D16), so a reader built for the 8-byte
answer parses a 0.6 card unchanged. A reader that needs the PUK state reads
capability bit 4 (or the response length) before it reads byte 8.

**Capabilities flags (byte 6):**

| Bit | Meaning |
|-----|---------|
| 0 | secp256k1 native (1) or software (0) |
| 1 | Schnorr signing supported |
| 2 | PIN protection available |
| 3 | `CLEAR_PIN` (0x43) supported — applet 0.5 and later; a build without it answers 0x43 with `6D00` |
| 4 | PUK: `SET_PUK` (0x44) and `UNBLOCK_PIN` (0x45) supported, and byte 8 present — applet 0.6 and later; a build without it answers both with `6D00` |
| 5–7 | Reserved (0) |

**PIN state 2 is not "no PIN".** A blocked card still has a PIN; it can never
be verified again (`VERIFY_PIN` answers `6983`), so every PIN-gated command
answers `6982` until the PIN is unblocked. `UNBLOCK_PIN` (0x45) with the
card's PUK is the one path out (D16); `CLEAR_PIN` is not one: it needs a
verified session, which a blocked card can never grant. A card with no PUK
(byte 8 = 0, or an applet before 0.6) or an exhausted one (byte 8 = 2) has no
path out, and its balance is stranded. A reader must treat 2 as "a PIN
exists", never as 0.

**PUK state is the card's, not the PIN's.** The PUK is set once, at
personalisation, and survives `CLEAR_PIN` and the `SET_PIN` after it: one
PUK per card, for every PIN the holder sets. The card never reveals it, so
the personaliser records it off the card (see
[Personalisation](#personalisation)).

**PIN state 1 is not for keeps.** The holder can remove the PIN with
`CLEAR_PIN` (D15), after which the card answers 0 again and spends with no
PIN, as a never-personalised card does. Read byte 7 on every tap; a reader
that remembers a card as PIN-set will prompt for a PIN the card no longer has
(`VERIFY_PIN` answers `6984`), and one that remembers it as PIN-free will send
a spend the card refuses with `6982`.

---

### GET_PUBKEY (0x10)

Returns the card's secp256k1 public key (compressed, 33 bytes). This key is generated once at install and never exported in private form. Used by the mint to set NUT-11 P2PK spending conditions.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 10 |
| P1 | 00 |
| P2 | 00 |
| Le | 21 |
| Response | 33-byte compressed public key |

**Errors:**

| SW | Meaning |
|----|---------|
| 9000 | OK |
| 6F00 | Key encoding not recognised (hardware error) |

---

### GET_BALANCE (0x11)

Returns the sum of all unspent proof amounts as a 4-byte big-endian uint32. Unit matches the keyset unit (sats or cents).

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 11 |
| P1 | 00 |
| P2 | 00 |
| Le | 04 |
| Response | 4-byte uint32 (big-endian) |

---

### GET_PROOF_COUNT (0x12)

Returns a 1-byte count of total proof slots that are non-empty (unspent + spent).

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 12 |
| P1 | 00 |
| P2 | 00 |
| Le | 01 |
| Response | 1-byte count |

---

### GET_PROOF (0x13)

Returns full proof data at a given slot index. Slot must be non-empty.

A spent slot is returned as the card holds it, and that is not always a proof:
a card pulled mid-`CLEAR_SPENT` leaves a slot that still reads `02` with some
of its data zeroed (see [CLEAR_SPENT](#clear_spent-0x31)).

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 13 |
| P1 | Slot index (0-based) |
| P2 | 00 |
| Le | 4E (78 bytes) |

**Response (78 bytes):**

| Offset | Length | Description |
|--------|--------|-------------|
| 0 | 1 | Status: `01`=unspent, `02`=spent |
| 1 | 8 | Keyset ID — the NUT-02 id as 8 **raw** bytes, e.g. `00 59 53 4c e0 bf a1 9a` for `0059534ce0bfa19a` |
| 9 | 4 | Amount (big-endian uint32) |
| 13 | 32 | Nonce — the 32-byte nonce from the NUT-10 P2PK secret, **not** the secret string |
| 45 | 33 | C point (compressed secp256k1) |

**Errors:**

| SW | Meaning |
|----|---------|
| 6A83 | Slot index out of range |
| 6A88 | Slot is empty |

---

### GET_SLOT_STATUS (0x14)

Lightweight bulk status read. Returns a 1-byte status for every slot (0=empty, 1=unspent, 2=spent), allowing the reader to enumerate without reading full proof data.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 14 |
| P1 | 00 |
| P2 | 00 |
| Le | 20 (32 bytes, one per slot) |
| Response | 32 bytes: one status byte per slot |

---

## Category 0x2x — Spend (PIN required if PIN is set — Profile B+)

If a PIN is set, the reader must call `VERIFY_PIN (0x40)` within the same NFC session before any spend or sign command (D13). "A PIN is set" includes the blocked state (GET_INFO byte 7 = 2): `VERIFY_PIN` can never succeed there, so every spend and sign command answers `6982` until `UNBLOCK_PIN (0x45)` replaces the PIN with the card's PUK (D16) — permanently, on a card with no PUK. Cards provisioned without a PIN keep tap-and-go behaviour, and so does a card whose holder has removed the PIN with `CLEAR_PIN (0x43)` (D15). The PIN session flag is transient: cleared on card deselect / tap end, by any failed PIN or PUK check, and by a successful `CLEAR_PIN` or `UNBLOCK_PIN` (see [Session State](#session-state-transient)).

### SPEND_PROOF (0x20)

Atomically marks a proof as spent (irreversible) and returns a NUT-11 P2PK Schnorr signature. The signature proves the card authorised this spend. The reader submits the proof + signature to the Cashu mint for redemption.

This is the **core payment operation**.

**PIN:** if a PIN is set, `VERIFY_PIN` must precede this command in the same
session (D13). A blocked PIN counts as set, and refuses until `UNBLOCK_PIN`
(for good, on a card with no PUK). The gate runs *before* the slot burn, so a
wrong, missing or blocked PIN never consumes a proof.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 20 |
| P1 | Slot index |
| P2 | 00 |
| Lc | 20 |
| Data | 32-byte message = SHA-256(UTF8(Proof.secret)) — see the note below |
| Le | 40 |
| Response | 64-byte Schnorr signature (R \|\| s, 32 bytes each) |

**Errors:**

| SW | Meaning |
|----|---------|
| 6985 | Proof already spent — double-spend blocked |
| 6A88 | Slot is empty |
| 6A83 | Slot index out of range |
| 6982 | PIN set (or blocked) and not verified in this session; once the PIN is blocked, until `UNBLOCK_PIN` |
| 6F00 | Signing failed (hardware error) |

**Note on message construction:** The reader computes

```
msg = SHA-256(UTF8(Proof.secret))
```

where `Proof.secret` is the reconstructed NUT-10 P2PK secret string — see
[NUT-XX.md — SPEND_PROOF Message Construction](NUT-XX.md#spend_proof--message-construction)
for the canonical definition and the reconstruction rules. That secret embeds
the proof's 32-byte nonce, which is what makes the message unique per proof and
so makes a captured signature useless against any other proof.

---

### SIGN_ARBITRARY (0x21)

Signs any 32-byte message with the card private key **without** consuming a proof. Used for:
- NUT-11 proof-of-ownership challenges (wallet queries card capability)
- Card authentication during provisioning
- Future NUT extensions requiring card identity proofs

**PIN:** gated like `SPEND_PROOF` (D13) — the signature is a spend
authorisation under the card's key, so an unverified session must not be able
to mint one. `6982` when a PIN is set (or blocked) and unverified in this
session.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 21 |
| P1 | 00 |
| P2 | 00 |
| Lc | 20 |
| Data | 32-byte message |
| Le | 40 |
| Response | 64-byte Schnorr signature (R \|\| s) |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | PIN set (or blocked) and not verified in this session; once the PIN is blocked, until `UNBLOCK_PIN` |
| 6F00 | Signing failed |

---

## Category 0x3x — Write (PIN required if PIN is set)

If PIN is set, the reader must call `VERIFY_PIN (0x40)` within the same NFC session before calling write commands. "PIN is set" includes the blocked state (GET_INFO byte 7 = 2), in which every write command answers `6982` until `UNBLOCK_PIN (0x45)` (D16). A card with no PIN — never personalised, or cleared with `CLEAR_PIN (0x43)` — writes without one. The PIN session flag is transient: cleared on card deselect / tap end, by any failed PIN or PUK check, and by a successful `CLEAR_PIN` or `UNBLOCK_PIN` (see [Session State](#session-state-transient)).

### LOAD_PROOF (0x30)

Stores a new proof in the next available empty slot. Used during card top-up (funding at flash-pos or via flash-mobile).

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 30 |
| P1 | 00 |
| P2 | 00 |
| Lc | 4D (77 bytes) |
| Data | 8-byte keyset_id (raw) + 4-byte amount + 32-byte nonce + 33-byte C point |
| Le | 01 |
| Response | 1-byte slot index assigned |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | Security condition not satisfied (PIN set or blocked, and not verified in this session) |
| 6986 | Card locked (`LOCK_CARD`) — writes disabled |
| 6A84 | No space — all slots occupied |

**Write order.** The card stores the 77 bytes, then marks the slot unspent
(D14, applet 0.4 and later; a card whose `SELECT` answers below `00 04` may
mark it first). A card that leaves the field mid-command leaves the slot empty
or holding the whole proof, never part of one marked unspent. The card does not
check for duplicates, so after a `LOAD_PROOF` whose answer was lost the proof
may or may not be on the card: read the slots (`GET_SLOT_STATUS`, `GET_PROOF`)
before sending it again.

---

### CLEAR_SPENT (0x31)

Garbage-collects all spent proof slots, freeing them for new proofs. Called after a top-up cycle to reclaim slot space. Requires PIN.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 31 |
| P1 | 00 |
| P2 | 00 |
| Le | 01 |
| Response | 1-byte count of slots freed |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | Security condition not satisfied (PIN set or blocked, and not verified in this session) |
| 6986 | Card locked (`LOCK_CARD`) — writes disabled |

**Write order.** Each spent slot's data is zeroed, then the slot is marked
empty (D14, applet 0.4 and later). A tear leaves a slot still spent, which the
next `CLEAR_SPENT` frees. Until then `GET_PROOF` returns the slot with status
`02` and some fields zeroed; the fill is not atomic, so which of them are
zeroed is not defined. Once `CLEAR_SPENT` has touched a spent slot, its data is
not a proof. Only the zeroed bytes set such a slot apart, so a reader that uses
a spent slot's data checks it first. `cardctl dump` skips a spent slot that
fails the card file's slot checks ([`CARD-FILE.md`](CARD-FILE.md#slot)). The
slot checks catch a zeroed amount and a `C` that is no longer a point. A tear
that zeroed only keyset or nonce bytes, or part of `C` whose x still lands on
the curve, passes them, and `dump` writes that slot as spent.

---

## Category 0x4x — Authentication

### VERIFY_PIN (0x40)

Verifies the provisioning PIN. On success, sets a transient session flag that permits the PIN-gated commands (spend, sign, write) for the remainder of this NFC tap, and resets the retry counter. On failure, decrements the retry counter and clears the session flag: a session that had verified is no longer authenticated, as with `OwnerPIN.check`.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 40 |
| P1 | 00 |
| P2 | 00 |
| Lc | 04–08 |
| Data | PIN bytes (4–8 bytes) |

**Errors:**

| SW | Meaning |
|----|---------|
| 63 CX | Wrong PIN — X retries remaining (e.g. `63 C2` = 2 retries left); the session's verification ends |
| 6983 | PIN blocked — max retries exhausted, GET_INFO byte 7 now 2. Answered by the try that exhausts the counter (not `63 C0`) and by every `VERIFY_PIN` after it, until `UNBLOCK_PIN` (0x45) replaces the PIN with the PUK (D16) |
| 6984 | PIN not set (use SET_PIN first) |

---

### SET_PIN (0x41)

Sets the provisioning PIN. May only be called **once per PIN lifecycle**: at card personalization, and again only after `CLEAR_PIN` has removed the PIN (D15). Subsequent PIN changes use `CHANGE_PIN`. If called when PIN is already set, returns `6985` — and a blocked PIN counts as set, so `SET_PIN` can never re-key a blocked card. The new PIN starts with the full try count.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 41 |
| P1 | 00 |
| P2 | 00 |
| Lc | 04–08 |
| Data | New PIN bytes |

**Errors:**

| SW | Meaning |
|----|---------|
| 6985 | PIN already set (or blocked) — use CHANGE_PIN |
| 6986 | Card locked (`LOCK_CARD`) |
| 6700 | Wrong data length (PIN must be 4–8 bytes) |

---

### CHANGE_PIN (0x42)

Changes the PIN. Requires the current PIN to be verified first in this session.

The card checks the current PIN in the data field again. A wrong one costs a
try and answers `63CX`, exactly as `VERIFY_PIN` does, and it ends the
session's verification: the next `CHANGE_PIN` answers `6982` until
`VERIFY_PIN` succeeds again, and that success resets the counter. So
`CHANGE_PIN` cannot run the counter down on its own; `6983` is listed below
because it shares `VERIFY_PIN`'s failure handling, and a reader should handle
it the same way.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 42 |
| P1 | 00 |
| P2 | 00 |
| Lc | Variable |
| Data | 1-byte old PIN length + old PIN + new PIN (4–8 bytes each) |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | Current PIN not verified in this session (always the case once the PIN is blocked, or after a failed check) |
| 63 CX | Wrong current PIN — X retries remaining; the session's verification ends |
| 6983 | PIN blocked — tries exhausted, GET_INFO byte 7 now 2 |
| 6986 | Card locked (`LOCK_CARD`) |
| 6700 | Wrong data length |

---

### CLEAR_PIN (0x43)

Removes the PIN (D15, applet 0.5). Requires the current PIN to be verified
first in this session, and presented again in the data field. On success the
card is as `SET_PIN` found it: GET_INFO byte 7 is `0`, the try counter is
back at its limit, every PIN-gated command runs with no PIN (the D12
tap-and-go behaviour), `VERIFY_PIN` answers `6984`, and `SET_PIN` may be
called again. The session's verification ends with the PIN it verified: a
`SET_PIN` in the same session gates spending at once, until `VERIFY_PIN`
succeeds with the new PIN.

The card checks the PIN in the data field again, with `CHANGE_PIN`'s failure
handling: a wrong one costs a try, answers `63CX`, and ends the session's
verification, so the next `CLEAR_PIN` answers `6982` until `VERIFY_PIN`
succeeds again. `CLEAR_PIN` cannot run the counter down on its own; `6983`
is listed below because the failure handling is shared.

**A blocked PIN cannot be cleared.** The verified session this command needs
is one a blocked card never grants (`VERIFY_PIN` answers `6983`), so a card
whose GET_INFO byte 7 is `2` answers `6982` here, with the right PIN, in
every session. Anything else would be an unblock path open to whoever holds
the card, since `VERIFY_PIN` is unauthenticated (ENG-615; D13). The unblock
path is [`UNBLOCK_PIN`](#unblock_pin-0x45), gated by the PUK (D16).

**The PUK is not cleared.** `CLEAR_PIN` removes the PIN and nothing else:
GET_INFO byte 8 is unchanged, `SET_PUK` still answers `6A89`, and after the
next `SET_PIN` the same PUK drives `UNBLOCK_PIN`.

**Write order.** There is one persistent write: the PIN state byte, set to
`0` after the PIN check, which the card writes atomically. A card that
leaves the field mid-command is PIN-set or it is not. The try counter is not
written by this command; the successful check that precedes the write has
already reset it to its limit (that is `OwnerPIN.check`'s contract), which
is what "the try counter is back at its limit" above rests on. Nothing reads
the counter behind state `0` in any case: `VERIFY_PIN` stops at `6984`, and
the next `SET_PIN` starts its PIN with the full try count.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 43 |
| P1 | 00 |
| P2 | 00 |
| Lc | Variable |
| Data | 1-byte PIN length + PIN (4–8 bytes); Lc must be exactly one more than the PIN length |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | Current PIN not verified in this session (always the case once the PIN is blocked, after a failed check, or when no PIN is set) |
| 63 CX | Wrong PIN — X retries remaining; the session's verification ends |
| 6983 | PIN blocked — tries exhausted, GET_INFO byte 7 now 2 |
| 6986 | Card locked (`LOCK_CARD`) |
| 6700 | Wrong data length (no length byte, PIN length outside 4–8, or Lc ≠ 1 + PIN length) |

---

### SET_PUK (0x44)

Sets the provisioning PUK (D16, applet 0.6), once per card. The PUK is the
one credential that can replace a PIN the holder has lost or blocked (see
[`UNBLOCK_PIN`](#unblock_pin-0x45)), so who may set it is the whole of this
command's design:

- **GET_INFO byte 7 = 0 (no PIN):** anyone, with no session. This is the
  personalisation order: `SET_PUK`, then `SET_PIN`.
- **Byte 7 = 1 (PIN set):** only a session that has verified the PIN
  (`6982` otherwise). Without that gate a reader in range could attach a PUK
  of its own to a personalised card, block the PIN with three guesses, and
  unblock it with the PUK it chose. The other personalisation order is
  therefore `SET_PIN`, `VERIFY_PIN`, `SET_PUK`.
- **Byte 7 = 2 (PIN blocked):** never. The gate is the verified session,
  which a blocked card never grants, so the reader that blocked a card cannot
  arm its own recovery. A blocked card with no PUK is stranded, as every card
  before 0.6 is.
- **Byte 8 ≠ 0:** never (`6A89`). A PUK is not changed, not replaced, and an
  exhausted one (byte 8 = 2) is not re-armed, by anyone.

The card never reveals the PUK. The personaliser records it off the card at
the moment it is set; where (the backend card registry, ENG-618) is not the
card's concern. `SET_PUK` does not open or end a session, and does not touch
the PIN or its try counter.

**Write order.** The PUK value is written first, then GET_INFO byte 8 is set
to `1`, as a single byte the card writes atomically (D14). A card that leaves
the field between the two holds a PUK that nothing reads — `UNBLOCK_PIN`
stops at byte 8 = 0 with `6A82` — and the next `SET_PUK` overwrites it.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 44 |
| P1 | 00 |
| P2 | 00 |
| Lc | Variable |
| Data | 1-byte PUK length + PUK (8–12 bytes, digits as bytes like the PIN); Lc must be exactly one more than the PUK length |

**Errors:**

| SW | Meaning |
|----|---------|
| 6A89 | PUK already set, or exhausted — a PUK is set once |
| 6982 | PIN set (or blocked) and not verified in this session |
| 6986 | Card locked (`LOCK_CARD`) |
| 6700 | Wrong data length (no length byte, PUK length outside 8–12, or Lc ≠ 1 + PUK length) |

---

### UNBLOCK_PIN (0x45)

Replaces the PIN, authorised by the PUK (D16, applet 0.6). The only path out
of GET_INFO byte 7 = 2: a blocked PIN gates every command until this
succeeds (ENG-615), and nothing else — not `CLEAR_PIN`, not `SET_PIN`, not
a reinstall with the balance intact — takes a card out of that state. It
also serves a PIN the holder has forgotten on a card that is not blocked:
byte 7 = 1 goes to 1 with the new PIN, byte 7 = 2 goes to 1, and the holder
cannot tell the two cases apart, so the card does not either.

No `VERIFY_PIN` precedes it: the PUK is the authority, and the card this
command rescues cannot open a session. On success GET_INFO byte 7 is `1`,
the new PIN's try counter is at its limit (3), the old PIN is gone, byte 8
is unchanged (a successful unblock does not consume the PUK; the same PUK
unblocks the card again), and **no session is open**: the command proved the
PUK, not the new PIN, so the session's verification — if there was one — ends,
and the holder sends `VERIFY_PIN` with the new PIN as usual.

**A wrong PUK** ends the session's PIN verification (as every failed check
does), costs one of the PUK's ten tries, and answers `63 CX` with the PUK
tries left: `63 C9` after the first wrong PUK. Unlike `VERIFY_PIN`, the try
that exhausts the counter answers `63 C0`, so a reader counting down sees the
count reach zero; it also sets byte 8 to `2`, after which every `UNBLOCK_PIN`
answers `6983` before any check runs, with the right PUK, in every session.
Exhaustion is terminal: `SET_PUK` refuses an exhausted card (`6A89`), so a
card that has lost its PUK to guessing has lost its recovery path, and a PIN
blocked on it is stranded. The PIN and its counter are never touched by a
failed `UNBLOCK_PIN`.

**Write order.** The PUK is checked first; nothing is written on a wrong PUK
but the PUK's own try counter (and byte 8, after the exhausting try). On a
right PUK the new PIN is written with its counter at the limit, then GET_INFO
byte 7 is set to `1`, last, as a single byte the card writes atomically (D14).
A card that leaves the field before that byte is `2` over the new PIN: the
card refuses `VERIFY_PIN` with `6983` on byte 7 alone (not only on an empty
counter), every gate holds, and the next `UNBLOCK_PIN` with the same PUK
finishes it. Nothing a reader can do with the torn card differs from what it
could do with the blocked one.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 45 |
| P1 | 00 |
| P2 | 00 |
| Lc | Variable |
| Data | 1-byte PUK length + PUK (8–12 bytes) + 1-byte new PIN length + new PIN (4–8 bytes); Lc must be exactly 2 + PUK length + new PIN length |

**Errors:**

| SW | Meaning |
|----|---------|
| 6A82 | PUK not set (GET_INFO byte 8 = 0) — nothing can unblock this card |
| 6983 | PUK exhausted (byte 8 = 2) — ten wrong PUKs; terminal. In this command the blocked authentication method is always the PUK, never the PIN |
| 6984 | PIN not set — nothing to unblock or replace; use `SET_PIN` |
| 63 CX | Wrong PUK — X PUK tries remaining (`63 C0` on the try that exhausts it, which also sets byte 8 to 2); the session's PIN verification ends |
| 6986 | Card locked (`LOCK_CARD`) — refused before the PUK gate, so no try is spent; a blocked PIN on a locked card stays blocked |
| 6700 | Wrong data length (a length byte missing, PUK length outside 8–12, new PIN length outside 4–8, or Lc ≠ 2 + PUK length + new PIN length) |

---

## Category 0x5x — Admin

### LOCK_CARD (0x50)

Permanently disables all write operations. Useful for lost/stolen card mitigation if the card is recovered. **Irreversible.** Requires PIN when one is set; a blocked PIN counts as set, so a blocked card cannot be locked. A locked card keeps the PIN and the PUK it has: `SET_PIN`, `CHANGE_PIN`, `CLEAR_PIN`, `SET_PUK` and `UNBLOCK_PIN` all answer `6986` — so a PIN that is blocked *after* the lock stays blocked, PUK or no PUK; the lock is the holder's irreversible choice and the PUK does not override it.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 50 |
| P1 | 00 |
| P2 | DE (deadbeef confirmation byte) |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | PIN set (or blocked) and not verified in this session |
| 6985 | Card already locked |

---

## Error Code Summary

| SW | Meaning |
|----|---------|
| 90 00 | Success |
| 63 CX | Wrong PIN, X retries remaining (the session's verification ends); from `UNBLOCK_PIN`, wrong PUK, X PUK tries remaining |
| 67 00 | Wrong length (Lc/Le) |
| 69 82 | Security condition not satisfied (PIN set or blocked, and not verified in this session) |
| 69 83 | Authentication method blocked (PIN blocked, GET_INFO byte 7 = 2; from `UNBLOCK_PIN`, PUK exhausted, byte 8 = 2) |
| 69 84 | Referenced data not usable (PIN not set) |
| 69 85 | Conditions not satisfied (already spent / already set / card already locked) |
| 69 86 | Command not allowed (card locked by `LOCK_CARD` — writes disabled) |
| 6A 82 | File not found (PUK not set — `UNBLOCK_PIN` has nothing to check against) |
| 6A 83 | Record not found (slot out of range) |
| 6A 84 | Not enough memory (no empty slots) |
| 6A 88 | Referenced data not found (slot empty) |
| 6A 89 | File already exists (PUK already set or exhausted — `SET_PUK` is once per card) |
| 6D 00 | Instruction not supported |
| 6E 00 | Class not supported |
| 6F 00 | No precise diagnosis (hardware / crypto error) |

---

## Proof Slot Layout

Each proof occupies exactly **78 bytes** of persistent EEPROM:

```
Offset  Len  Field
------  ---  -----
0       1    Status (00=empty, 01=unspent, 02=spent)
1       8    Keyset ID (NUT-02 id as 8 RAW bytes, e.g. 00 59 53 4c e0 bf a1 9a)
9       4    Amount (big-endian uint32)
13      32   Nonce (32-byte nonce from the NUT-10 P2PK secret)
45      33   C point (compressed secp256k1, 02/03 prefix)
```

The keyset id is stored **raw**, not as ASCII text. A NUT-02 id is 16 hex
characters, which is 8 bytes raw but 16 bytes as ASCII — storing it as text
would fit only half the id and match no keyset at the mint.

The 32-byte field is the **nonce**, not the secret. A NUT-10 P2PK secret is a
JSON string of ~150 bytes; the card stores the nonce and a reader rebuilds the
secret from it plus `GET_PUBKEY`. See [`NUT-XX.md`](NUT-XX.md).

Total: 32 slots × 78 bytes = **2,496 bytes** EEPROM for proof storage.

---

## Session State (Transient)

The following flags are held in transient RAM and cleared on card deselect:

| Flag | Set by | Cleared by |
|------|--------|-----------|
| `pin_verified` | VERIFY_PIN (success) | Deselect / tap end / any failed PIN check (VERIFY_PIN, CHANGE_PIN or CLEAR_PIN) / any failed PUK check (UNBLOCK_PIN) / CLEAR_PIN or UNBLOCK_PIN (success — the verified PIN no longer exists) |

---

## Personalisation

A card leaves the factory with no PIN and no PUK (GET_INFO bytes 7 and 8
both `0`). The recommended order is `SET_PUK`, then `SET_PIN`: with no PIN on
the card `SET_PUK` needs no session, and the card is never in the field with
a PIN it cannot recover. The other order works too — `SET_PIN`, `VERIFY_PIN`,
`SET_PUK` — and is the one for a card personalised before 0.6 existed, whose
holder adds a PUK in their own session.

**Verify bytes 7 and 8 are both `0` before `SET_PUK`; a card that is not is
not yours to issue.** `SET_PUK` is free on a card with no PIN, so a card that
already reports a PUK (byte 8 = `1`) and no PIN (byte 7 = `0`) is one that
somebody else armed between the factory and your reader — one APDU in NFC
range is enough. The `6A89` your own `SET_PUK` then gets is not a duplicate
run: whoever holds that PUK can block the issued card's PIN with three wrong
tries and `UNBLOCK_PIN` it to a PIN of their choosing, and the balance is
theirs ([SECURITY-MODEL #16](../docs/SECURITY-MODEL.md)). The PUK cannot be
replaced; do not issue the card, reinstall the CAP (which regenerates the key
and clears both states) and personalise again.

```
Personaliser                    Card
  |                              |
  |--- SELECT APPLICATION -----> |
  |<-- 00 06 90 00 -------------|
  |--- GET_INFO (0x01) --------> |
  |<-- … 1F 00 00 + 90 00 ------|  (caps, PIN unset, PUK unset: yours to issue)
  |--- SET_PUK (0x44) ---------> |  (8–12 digits; generated, not chosen)
  |<-- 90 00 -------------------|
  |--- SET_PIN (0x41) ---------> |  (the holder's PIN)
  |<-- 90 00 -------------------|
  |--- GET_INFO (0x01) --------> |
  |<-- … 1F 01 01 + 90 00 ------|  (caps, PIN set, PUK set)
```

The PUK is generated by the personaliser and **recorded off the card** at the
moment `SET_PUK` succeeds; the card never reveals it, and a PUK that is not
recorded is a PUK that does not exist. Its custody is the backend card
registry's (ENG-618), which releases it to the card's owning account after
authentication; the card does not assume anything about where it lives, only
that `UNBLOCK_PIN` is answered by whoever presents it. One PUK serves every
PIN the holder sets afterwards: `CLEAR_PIN` and `SET_PIN` leave it in place.

---

## Provisioning Flow (Top-Up)

```
Reader                          Card
  |                              |
  |--- SELECT APPLICATION -----> |
  |<-- 90 00 -------------------|
  |--- VERIFY_PIN (0x40) ------> |  (PIN set at personalization)
  |<-- 90 00 -------------------|
  |--- CLEAR_SPENT (0x31) -----> |  (reclaim spent slots)
  |<-- count + 90 00 -----------|
  |--- LOAD_PROOF (0x30) ------> |  (repeat for each proof)
  |<-- slot_idx + 90 00 --------|
  |--- GET_BALANCE (0x11) -----> |  (verify new balance)
  |<-- balance + 90 00 ---------|
```

## Payment Flow (Offline Spend)

```
POS Terminal                    Card
  |                              |
  |--- SELECT APPLICATION -----> |
  |<-- 90 00 -------------------|
  |--- GET_BALANCE (0x11) -----> |
  |<-- balance + 90 00 ---------|
  |--- GET_SLOT_STATUS (0x14) -> |
  |<-- slot statuses -----------|
  |--- GET_PROOF (0x13, idx) --> |  (read proof to pay with)
  |<-- proof data + 90 00 ------|
  |--- SPEND_PROOF (0x20, idx) > |  (sign + mark spent atomically)
  |<-- 64-byte signature --------|
  |                              |
  [Terminal submits proof + sig to Cashu mint via Lightning/HTTP]
```
