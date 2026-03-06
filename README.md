# cashu-javacard

A JavaCard applet implementing the [Cashu](https://cashu.space) ecash protocol for offline NFC bearer payments.

## Overview

This applet runs on NFC JavaCard chips (ISO 14443-4 Type 4) and enables **true offline Cashu payments** — customers tap a physical card at a merchant terminal, and the merchant receives valid Cashu proofs without requiring an internet connection at point of sale.

This is the reference implementation for **NUT-XX: Cashu NFC Card Protocol**, Profile B (Bearer/Offline).

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Top-up (online)                                            │
│  flash-mobile / flash-pos → Flash backend → forge.flashapp.me │
│                                      ↓                       │
│                              Cashu proofs                     │
│                                      ↓                        │
│                         [NFC write to JavaCard]              │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  Payment (offline)                                           │
│  Customer taps card → flash-pos reads proofs (no internet)   │
│  Merchant verifies mint signature locally → queues redemption │
│  Later: flash-pos redeems proofs online with forge.flashapp.me│
└─────────────────────────────────────────────────────────────┘
```

## Card Capabilities

- **Proof storage**: Multiple Cashu denomination proofs in EEPROM (hardware-persistent)
- **Spend protection**: Non-resettable hardware spend counter per proof slot
- **secp256k1**: On-chip EC key generation + Schnorr/ECDSA signing for NUT-11 P2PK
- **APDU interface**: Standard JavaCard command set for provisioning and payment

## Supported Hardware

| Chip | Status | Notes |
|------|--------|-------|
| Feitian JavaCard 3.0.4 | ✅ Target (v1) | ~$2/card at volume |
| NXP JCOP4 (SmartMX3) | ✅ Target (v2) | CC EAL 5+, ~$5/card |
| NXP NTAG 424 DNA | ❌ | Insufficient memory, no EC crypto |

## APDU Command Set

See [`spec/APDU.md`](spec/APDU.md) for full command reference.

| CLA | INS | Command | Description |
|-----|-----|---------|-------------|
| 0xB0 | 0x01 | SELECT | Standard ISO SELECT AID |
| 0xB0 | 0x10 | GET_PUBKEY | Return card's secp256k1 public key |
| 0xB0 | 0x11 | GET_BALANCE | Sum of unspent proof amounts |
| 0xB0 | 0x12 | GET_PROOF_COUNT | Number of proof slots (spent + unspent) |
| 0xB0 | 0x13 | GET_PROOF | Return proof at index (amount, id, secret, C) |
| 0xB0 | 0x20 | SPEND_PROOF | Mark proof as spent + return NUT-11 signature |
| 0xB0 | 0x30 | LOAD_PROOF | Store a new proof (provisioning, authenticated) |
| 0xB0 | 0x31 | CLEAR_SPENT | Garbage-collect spent proof slots |

## AID

`D2 76 00 00 85 01 02` (Cashu, v2)

## Project Structure

```
applet/         JavaCard applet source (Java Card 3.0.4+)
spec/           Protocol specs (APDU.md, NUT-XX.md)
test/           jCardSim-based test suite
docs/           Architecture and provisioning guides
scripts/        Provisioning helpers for flash-pos
```

## Building

Requires [JavaCard SDK 3.0.4+](https://www.oracle.com/java/technologies/javacard-downloads.html) and JDK 11+.

```bash
./gradlew buildCap
# Output: applet/cap/CashuApplet.cap
```

## Testing

```bash
./gradlew test
# Runs full jCardSim test suite (no hardware required)
```

## Spec: NUT-XX

The protocol specification for Cashu NFC Card Protocol is being drafted in [`spec/NUT-XX.md`](spec/NUT-XX.md) and will be submitted to [cashubtc/nuts](https://github.com/cashubtc/nuts) for community review.

## Related Projects

- [forge.flashapp.me](https://forge.flashapp.me) — Flash Cashu mint (Nutshell 0.18.0)
- [flash-pos](https://github.com/lnflash/flash-pos) — merchant point-of-sale app
- [flash-mobile](https://github.com/lnflash/flash-mobile) — customer mobile app
- [Numo](https://github.com/cashubtc/Numo) — Android Cashu NFC PoS (Profile A reference)

## License

MIT
