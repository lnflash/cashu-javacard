# cashu-javacard

A JavaCard applet implementing the [Cashu](https://cashu.space) ecash protocol for offline NFC bearer payments.

## Overview

This applet runs on NFC JavaCard chips (ISO 14443-4 Type 4) and enables **true offline Cashu payments** â customers tap a physical card at a merchant terminal, and the merchant receives valid Cashu proofs without requiring an internet connection at point of sale.

This is the reference implementation for **NUT-XX: Cashu NFC Card Protocol**, Profile B (Bearer/Offline).

## Architecture

```
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â  Top-up (online)                                            â
â  flash-mobile / flash-pos â Flash backend â forge.flashapp.me â
â                                      â                       â
â                              Cashu proofs                     â
â                                      â                        â
â                         [NFC write to JavaCard]              â
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
â  Payment (offline)                                           â
â  Customer taps card â flash-pos reads proofs (no internet)   â
â  Merchant verifies mint signature locally â queues redemption â
â  Later: flash-pos redeems proofs online with forge.flashapp.meâ
âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
```

## Card Capabilities

- **Proof storage**: Multiple Cashu denomination proofs in EEPROM (hardware-persistent)
- **Spend protection**: Non-resettable hardware spend counter per proof slot
- **secp256k1**: On-chip EC key generation + Schnorr/ECDSA signing for NUT-11 P2PK
- **APDU interface**: Standard JavaCard command set for provisioning and payment

## Supported Hardware

| Chip | Status | Notes |
|------|--------|-------|
| Feitian JavaCard 3.0.4 | â Target (v1) | ~$2/card at volume |
| NXP JCOP4 (SmartMX3) | â Target (v2) | CC EAL 5+, ~$5/card |
| NXP NTAG 424 DNA | â | Insufficient memory, no EC crypto |

## APDU Command Set

See [`spec/APDU.md`](spec/APDU.md) for full command reference.

| CLA | INS | Command | Description |

`D2 76 00 00 85 01 02` (Cashu, v2)

## Documentation

- [User Guide & NFC Flow](docs/USER_GUIDE.md) — How to load and use the card.

## Project Structure

```
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

- [forge.flashapp.me](https://forge.flashapp.me) â Flash Cashu mint (Nutshell 0.18.0)
- [flash-pos](https://github.com/lnflash/flash-pos) â merchant point-of-sale app
- [flash-mobile](https://github.com/lnflash/flash-mobile) â customer mobile app
- [Numo](https://github.com/cashubtc/Numo) â Android Cashu NFC PoS (Profile A reference)

## License

MIT
