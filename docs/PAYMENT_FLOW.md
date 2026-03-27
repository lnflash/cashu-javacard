# NFC Payment Flow — Cashu JavaCard

This document describes the complete NFC payment lifecycle for Cashu JavaCard, from card provisioning through to merchant redemption.

---

## Overview

Cashu JavaCard enables a **two-phase payment model**:

| Phase | Connectivity | Who | What |
|-------|-------------|-----|------|
| **Top-Up** | Online | Customer | Load proofs onto card |
| **Payment** | Offline | Customer + Merchant | Spend proofs via NFC tap |
| **Redemption** | Online | Merchant | Redeem spent proofs at mint |

The card itself requires **no internet** — it's a pure NFC device. Internet is only needed at the endpoints (mint, wallet app, POS backend).

---

## Phase 1: Card Provisioning & Top-Up

### 1.1 Card Setup (One-Time)

```
  Merchant / Developer
        │
        ▼
  ┌──────────────────────┐
  │  Build & Install      │
  │  CashuApplet.cap      │
  │  onto JavaCard        │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │  Card generates its   │
  │  secp256k1 keypair    │
  │  (on-chip, permanent) │
  └──────────┬───────────┘
             │
             ▼
  ┌──────────────────────┐
  │  GET_PUBKEY returns   │
  │  33-byte compressed   │
  │  public key           │
  └──────────────────────┘
```

The card's public key (`P_card`) becomes its permanent identity. All proofs loaded onto this card must be locked to `P_card` using NUT-11 P2PK spending conditions.

### 1.2 Loading Proofs

```
  Customer          flash-mobile           Cashu Mint
     │                   │                     │
     │  "Load 1000 sats" │                     │
     │──────────────────►│                     │
     │                   │  Request proofs      │
     │                   │  locked to P_card    │
     │                   │────────────────────►│
     │                   │                     │
     │                   │  Proofs + signatures │
     │                   │◄────────────────────│
     │                   │                     │
     │  Tap card         │                     │
     │  (NFC)            │                     │
     │◄─────────────────►│                     │
     │                   │                     │
     │  APDU: LOAD_PROOF │                     │
     │  (×N for N proofs)│                     │
     │──────────────────►│ (writes to card)    │
     │                   │                     │
     │  Response:        │                     │
     │  slot index + 9000│                     │
     │◄──────────────────│                     │
     │                   │                     │
     │  ✅ Card loaded    │                     │
```

#### What gets written (per proof)

Each `LOAD_PROOF` writes 77 bytes to one of 32 slots:

| Field | Size | Description |
|-------|------|-------------|
| Keyset ID | 8 bytes | Identifies the mint's keyset |
| Amount | 4 bytes | Value in sats (big-endian uint32) |
| Secret (nonce) | 32 bytes | Random nonce from the P2PK Secret |
| C (signature) | 33 bytes | Mint's compressed secp256k1 blind signature |

#### Example: Loading 1000 sats

Suppose the mint returns 4 proofs: 500 + 250 + 125 + 125 sats = 1000 sats.

```
Slot 0: 500 sats  (unspent)  ← LOAD_PROOF
Slot 1: 250 sats  (unspent)  ← LOAD_PROOF
Slot 2: 125 sats  (unspent)  ← LOAD_PROOF
Slot 3: 125 sats  (unspent)  ← LOAD_PROOF

GET_BALANCE → 1000 ✅
```

---

## Phase 2: Payment (NFC Tap)

### 2.1 Full Balance Payment

```
  Customer            flash-pos (Merchant)
     │                      │
     │  Tap card (NFC)      │
     │◄────────────────────►│
     │                      │
     │  GET_BALANCE         │
     │◄─────────────────────│
     │  Response: 1000 sats │
     │──────────────────────►│
     │                      │
     │  "Pay 1000 sats?"    │
     │◄─────────────────────│
     │                      │
     │  Customer confirms   │
     │──────────────────────►│
     │                      │
     │  SPEND_PROOF(slot 0) │  SHA256(secret) → msg
     │◄─────────────────────│
     │                      │
     │  Card marks spent    │
     │  + signs message     │
     │  (Schnorr, on-chip)  │
     │                      │
     │  Response:           │
     │  64-byte signature   │
     │──────────────────────►│
     │                      │
     │  SPEND_PROOF(slot 1) │  (repeat for each proof)
     │◄─────────────────────│
     │  Response: signature │
     │──────────────────────►│
     │                      │
     │  ... (slots 2, 3)    │
     │                      │
     │  ✅ Payment complete  │
     │                      │
     │                      │  (later, online)
     │                      │  Redeem all proofs
     │                      │────────────────────► Mint
```

### 2.2 Partial Amount Payment

For amounts smaller than the card's balance, the POS selects a subset of proofs:

```
  Card state before:          Card state after (pay 375 sats):
  ┌────────┬────────┐        ┌────────┬────────┐
  │Slot 0  │500 sat │        │Slot 0  │500 sat │ ← spent (500 > 375, change = 125)
  │Slot 1  │250 sat │        │Slot 1  │250 sat │ ← spent (partial)
  │Slot 2  │125 sat │        │Slot 2  │125 sat │ ← spent (exactly covers remainder)
  │Slot 3  │125 sat │        │Slot 3  │125 sat │ ← untouched
  └────────┴────────┘        └────────┴────────┘
  Total: 1000 sats           Remaining: 125 sats
```

The POS needs to handle change — typically by requesting new proofs from the mint for the difference and writing them back to the card.

### 2.3 Core Spend Sequence (APDU Level)

```
Reader                              Card
  │                                  │
  │  SELECT AID                      │
  │  00 A4 04 00 07 D2760000850102  │
  │─────────────────────────────────►│
  │  Response: 0000 9000             │
  │◄─────────────────────────────────│
  │                                  │
  │  GET_BALANCE                     │
  │  B0 11 00 00                    │
  │─────────────────────────────────►│
  │  Response: 00 00 03 E8 9000      │
  │◄─────────────────────────────────│
  │  (1000 sats available)           │
  │                                  │
  │  GET_PROOF (slot 0)              │
  │  B0 13 00 00                    │
  │─────────────────────────────────►│
  │  Response: [proof data] 9000     │
  │◄─────────────────────────────────│
  │                                  │
  │  Compute msg = SHA256(secret)    │
  │                                  │
  │  SPEND_PROOF (slot 0)            │
  │  B0 20 00 00 20 [32-byte msg]   │
  │─────────────────────────────────►│
  │                                  │
  │  Card:                           │
  │  1. Check status == unspent      │
  │  2. Set status = spent (atomic)  │
  │  3. Sign msg with privkey        │
  │                                  │
  │  Response: [64-byte sig] 9000    │
  │◄─────────────────────────────────│
  │                                  │
  │  (repeat for each proof to spend)│
```

**Important**: `SPEND_PROOF` is atomic — the proof is marked spent **before** the signature is generated. If signing fails (hardware error), the proof is still spent. This prevents double-spend.

---

## Phase 3: Merchant Redemption

After collecting proofs from customer payments, the merchant redeems them at the Cashu mint when online:

```
  flash-pos (Merchant)          Cashu Mint
        │                          │
        │  POST /melt               │
        │  {                        │
        │    "proofs": [...],       │
        │    "signatures": [...],   │
        │    "amount": 1000,        │
        │    "unit": "sat"          │
        │  }                        │
        │──────────────────────────►│
        │                          │
        │  Mint verifies:           │
        │  1. Proof signatures      │
        │  2. P2PK spend signatures │
        │  3. No double-spend       │
        │                          │
        │  Response:                │
        │  { "paid": true }         │
        │◄──────────────────────────│
        │                          │
        │  ✅ Merchant credited      │
```

---

## Error Handling

### Common APDU Status Words

| SW | Meaning | Action |
|----|---------|--------|
| `90 00` | Success | — |
| `6A 83` | Slot index out of range | Check slot is 0–31 |
| `6A 88` | Slot is empty | Load proofs first |
| `69 85` | Proof already spent | This proof cannot be reused |
| `69 82` | PIN required | Call `VERIFY_PIN` first |
| `69 83` | PIN blocked | Card locked — delete + reinstall |
| `63 CX` | Wrong PIN | X retries remaining |
| `6A 84` | No space | All 32 slots full — call `CLEAR_SPENT` |

### Double-Spend Protection

```
SPEND_PROOF(slot 0)  →  9000 ✅  (proof marked spent)
SPEND_PROOF(slot 0)  →  6985 ❌  (already spent — blocked by hardware)
```

The `6985` error is **unrecoverable** — there is no APDU to reset a spent proof to unspent. The only way to reclaim the slot is `CLEAR_SPENT`, which zeros the entire slot (not undoing the spend).

---

## Timing & Performance

| Operation | Typical NFC Duration | Notes |
|-----------|---------------------|-------|
| SELECT | ~50ms | One-time per session |
| GET_BALANCE | ~30ms | Fast, no crypto |
| GET_PROOF | ~40ms | Fast, no crypto |
| LOAD_PROOF | ~200ms | Includes EEPROM write |
| SPEND_PROOF | ~500ms | Includes Schnorr signing |
| CLEAR_SPENT | ~300ms | Multiple EEPROM erases |

A typical payment (SELECT + GET_BALANCE + 4×SPEND_PROOF) completes in under 3 seconds over NFC.

---

## Data Reconstruction

After spending, the merchant needs to reconstruct the full Cashu `Proof` object for mint redemption:

```python
import json, hashlib

# Data from the card
keyset_id = "0059534ce0bfa19a"
amount = 8
nonce = "916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e"
C = "024a43eddcf0e42dad32ca5c0e82e51d7a38e7a48b80e89d2e17cc94abb02c04c3"
P_card = "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2"

# Reconstruct the NUT-10 P2PK secret (no spaces, exact key order)
secret = json.dumps([
    "P2PK",
    {
        "nonce": nonce,
        "data": P_card,
        "tags": [["sigflag", "SIG_INPUTS"]]
    }
], separators=(",", ":"))

# The proof for mint redemption
proof = {
    "id": keyset_id,
    "amount": amount,
    "secret": secret,
    "C": C,
    "witness": json.dumps({
        "signatures": ["<64-byte Schnorr signature from SPEND_PROOF>"]
    })
}
```

> **Important**: The `secret` JSON must be serialized **without spaces** and with keys in the exact order shown above. This ensures consistent hashing for signature verification.

---

## See Also

- [User Guide](USER_GUIDE.md) — Getting started and FAQ
- [APDU Command Reference](../spec/APDU.md) — Full byte-level command spec
- [NUT-XX Protocol Spec](../spec/NUT-XX.md) — Complete protocol specification
- [Architecture](ARCHITECTURE.md) — On-card data model and internals
- [Hardware Deployment](HARDWARE_DEPLOYMENT.md) — Building and installing the applet
