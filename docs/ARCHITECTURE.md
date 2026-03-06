# Architecture

## On-Card Data Model

Each proof occupies exactly 78 bytes of EEPROM:

```
Offset  Size  Field
0       1     status (0=empty, 1=unspent, 2=spent)
1       8     keyset_id (hex, 8 bytes)
9       4     amount (uint32, big-endian, sats)
13      32    secret (x — the Cashu proof secret)
45      33    C (compressed secp256k1 point — the mint's blind signature)
```

With 32 slots × 78 bytes = 2,496 bytes of proof storage, plus the EC keypair (~64 bytes) and applet code.

## Key Management

- Card keypair generated at install time using `KeyPair.genKeyPair()`
- Private key stored in JavaCard's protected key storage (never in `byte[]`)
- Public key returned via `GET_PUBKEY` and used as the card's identity
- For NUT-11: spending conditions are bound to the card's public key

## Spend Protection

`SPEND_PROOF` sets `proofStorage[offset + STATUS] = STATUS_SPENT` atomically before signing. Once set to `STATUS_SPENT`, no APDU can reset it (no such command exists). The only reclaiming of spent slots is `CLEAR_SPENT`, which zeros the entire slot for fresh proof loading — not undoing the spend.
