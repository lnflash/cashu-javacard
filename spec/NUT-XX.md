# NUT-XX: Cashu NFC Card Protocol

> **Status: Draft** — Implementation in progress at [lnflash/cashu-javacard](https://github.com/lnflash/cashu-javacard). Targeting submission to cashubtc/nuts after reference implementation is complete.

## Abstract

This NUT defines a protocol for storing and spending Cashu proofs on physical NFC cards, enabling offline point-of-sale payments. Two profiles are defined to accommodate different chip capabilities.

## Profiles

### Profile A — Reference (Online)

- **Chip class**: NTAG 424 DNA or equivalent (AES-128 CMAC, ~256 bytes NDEF)
- **Balance storage**: Server-side (mint or backend maintains balance per card ID)
- **Authentication**: Hardware AES CMAC (SUN message) proves physical card presence
- **Connectivity**: Online required per payment
- **Double-spend**: Prevented server-side
- **Reference**: Compatible with Numo (cashubtc/Numo)

### Profile B — Bearer (Offline)

- **Chip class**: JavaCard 3.0.4+ with secp256k1 support (e.g., Feitian, NXP JCOP4)
- **Balance storage**: On-card EEPROM (Cashu proofs stored directly)
- **Authentication**: Hardware EC key (secp256k1 keypair generated on-chip)
- **Connectivity**: Offline payment supported; merchant redeems online later
- **Double-spend**: Hardware spend counter (non-resettable) + offline risk accepted for small amounts
- **Reference**: lnflash/cashu-javacard

## Profile B: Bearer Card Protocol

### Card Provisioning (Online)

```
1. flash-pos calls Flash backend: POST /api/v1/cards/provision
2. Flash backend calls mint: POST /v1/mint/quote/bolt11 (amount)
3. User pays Lightning invoice
4. Flash backend calls mint: POST /v1/mint (blind messages)
5. Flash backend returns proof bundle to flash-pos
6. flash-pos writes proofs to card via NFC APDU: LOAD_PROOF × N
7. Card stores proofs in EEPROM. Card is ready.
```

### Payment (Offline)

```
1. Customer taps card at merchant flash-pos
2. flash-pos sends: GET_BALANCE → verify sufficient funds
3. flash-pos sends: GET_PROOF[n] for required denominations
4. flash-pos sends: SPEND_PROOF[n] → card marks proof spent (irreversible)
                                    → card returns NUT-11 P2PK signature
5. flash-pos stores (proof, signature) locally
6. When online: flash-pos calls mint POST /v1/melt or /v1/swap to redeem
```

### Offline Verification by Merchant

The merchant can verify proof validity without internet by:
1. Checking proof structure is well-formed
2. Verifying `C = k * hash_to_curve(secret)` using the mint's known public key
3. Verifying the NUT-11 spending condition signature with the card's public key

This confirms the proof was legitimately issued by the mint and authorized by this specific card.

## APDU Specification

See [`APDU.md`](APDU.md) for complete command reference.

## AID

`D2 76 00 00 85 01 02`

- `D2 76 00 00 85`: NFC Forum AID prefix
- `01`: Cashu
- `02`: Profile B (Bearer)

## Security Considerations

- Card private key is generated on-chip and never exported
- Proof secrets are stored in protected EEPROM, inaccessible without SELECT + authentication
- Spend counters are non-resettable; a spent proof slot cannot be unmarked
- Offline double-spend risk: a determined attacker with chip-level access could potentially clone proof data before spend. Mitigated by: hardware protection on JCOP4 (CC EAL 5+), and the same risk tolerance as physical cash for small amounts.
- Recommended maximum card balance: 100,000 sats (hardware-dependent)

## Open Questions

- [ ] Exact encoding of proof bundle in APDU data field (CBOR vs raw bytes)
- [ ] PIN/password authentication before SPEND_PROOF (optional or required?)
- [ ] Change handling: when paying partial amount, how is change returned to card?
- [ ] Key derivation: should card keypair be derivable from a user seed for recovery?

## References

- [NUT-00](https://github.com/cashubtc/nuts/blob/main/00.md): Notation and models
- [NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md): Pay to Public Key (P2PK)
- [Numo](https://github.com/cashubtc/Numo): Android Cashu NFC PoS (Profile A)
- [NXP NTAG 424 DNA](https://www.nxp.com/products/rfid-nfc/nfc-hf/ntag/ntag-for-tags-labels/ntag-424-dna): Profile A chip reference
