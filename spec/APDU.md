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

**Response (8 bytes):**

| Offset | Length | Description |
|--------|--------|-------------|
| 0 | 1 | Major version |
| 1 | 1 | Minor version |
| 2 | 1 | Max proof slots |
| 3 | 1 | Unspent proof count |
| 4 | 1 | Spent proof count |
| 5 | 1 | Empty slot count |
| 6 | 1 | Capabilities flags (see below) |
| 7 | 1 | PIN state (0=unset, 1=set, 2=locked) |

**Capabilities flags (byte 6):**

| Bit | Meaning |
|-----|---------|
| 0 | secp256k1 native (1) or software (0) |
| 1 | Schnorr signing supported |
| 2 | PIN protection available |
| 3–7 | Reserved (0) |

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
| 1 | 8 | Keyset ID (hex string bytes, e.g. `30 30 35 39 35 33 34 63`) |
| 9 | 4 | Amount (big-endian uint32) |
| 13 | 32 | Secret (x) |
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

## Category 0x2x — Spend (no PIN required — bearer semantics)

Spending does not require PIN. The card is a bearer instrument; physical possession authorises payment. The mint enforces validity via Cashu proof verification.

### SPEND_PROOF (0x20)

Atomically marks a proof as spent (irreversible) and returns a NUT-11 P2PK Schnorr signature. The signature proves the card authorised this spend. The reader submits the proof + signature to the Cashu mint for redemption.

This is the **core payment operation**.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 20 |
| P1 | Slot index |
| P2 | 00 |
| Lc | 20 |
| Data | 32-byte message (SHA-256 of the spending transaction) |
| Le | 40 |
| Response | 64-byte Schnorr signature (R \|\| s, 32 bytes each) |

**Errors:**

| SW | Meaning |
|----|---------|
| 6985 | Proof already spent — double-spend blocked |
| 6A88 | Slot is empty |
| 6A83 | Slot index out of range |
| 6F00 | Signing failed (hardware error) |

**Note on message construction:** The reader computes `msg = SHA-256(keyset_id || secret || amount || recipient_pubkey)`. This binds the signature to the specific proof and intended recipient, preventing replay.

---

### SIGN_ARBITRARY (0x21)

Signs any 32-byte message with the card private key **without** consuming a proof. Used for:
- NUT-11 proof-of-ownership challenges (wallet queries card capability)
- Card authentication during provisioning
- Future NUT extensions requiring card identity proofs

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
| 6F00 | Signing failed |

---

## Category 0x3x — Write (PIN required if PIN is set)

If PIN is set, the reader must call `VERIFY_PIN (0x40)` within the same NFC session before calling write commands. The PIN session flag is transient (cleared on card deselect / tap end).

### LOAD_PROOF (0x30)

Stores a new proof in the next available empty slot. Used during card top-up (funding at flash-pos or via flash-mobile).

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 30 |
| P1 | 00 |
| P2 | 00 |
| Lc | 4D (77 bytes) |
| Data | 8-byte keyset_id + 4-byte amount + 32-byte secret + 33-byte C point |
| Le | 01 |
| Response | 1-byte slot index assigned |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | Security condition not satisfied (PIN required but not verified) |
| 6A84 | No space — all slots occupied |

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
| 6982 | Security condition not satisfied |

---

## Category 0x4x — Authentication

### VERIFY_PIN (0x40)

Verifies the provisioning PIN. On success, sets a transient session flag that permits write operations for the remainder of this NFC tap. On failure, decrements the retry counter.

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
| 63 CX | Wrong PIN — X retries remaining (e.g. `63 C2` = 2 retries left) |
| 6983 | PIN blocked — max retries exhausted; card locked |
| 6984 | PIN not set (use SET_PIN first) |

---

### SET_PIN (0x41)

Sets the provisioning PIN. May only be called **once** (during card personalization). Subsequent PIN changes use `CHANGE_PIN`. If called when PIN is already set, returns `6985`.

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
| 6985 | PIN already set — use CHANGE_PIN |
| 6700 | Wrong data length (PIN must be 4–8 bytes) |

---

### CHANGE_PIN (0x42)

Changes the PIN. Requires the current PIN to be verified first in this session.

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
| 6982 | Current PIN not verified |
| 6700 | Wrong data length |

---

## Category 0x5x — Admin

### LOCK_CARD (0x50)

Permanently disables all write operations. Useful for lost/stolen card mitigation if the card is recovered. **Irreversible.** Requires PIN.

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 50 |
| P1 | 00 |
| P2 | DE (deadbeef confirmation byte) |

**Errors:**

| SW | Meaning |
|----|---------|
| 6982 | PIN not verified |
| 6985 | Card already locked |

---

## Error Code Summary

| SW | Meaning |
|----|---------|
| 90 00 | Success |
| 63 CX | Wrong PIN, X retries remaining |
| 67 00 | Wrong length (Lc/Le) |
| 69 82 | Security condition not satisfied (PIN required) |
| 69 83 | Authentication method blocked (PIN locked) |
| 69 84 | Referenced data not usable (PIN not set) |
| 69 85 | Conditions not satisfied (already spent / already set) |
| 6A 83 | Record not found (slot out of range) |
| 6A 84 | Not enough memory (no empty slots) |
| 6A 88 | Referenced data not found (slot empty) |
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
1       8    Keyset ID (8 ASCII hex bytes, e.g. "0059534c")
9       4    Amount (big-endian uint32)
13      32   Secret (x)
45      33   C point (compressed secp256k1, 02/03 prefix)
```

Total: 32 slots × 78 bytes = **2,496 bytes** EEPROM for proof storage.

---

## Session State (Transient)

The following flags are held in transient RAM and cleared on card deselect:

| Flag | Set by | Cleared by |
|------|--------|-----------|
| `pin_verified` | VERIFY_PIN (success) | Deselect / tap end |

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
