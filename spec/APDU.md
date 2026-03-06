# APDU Command Reference

JavaCard Cashu Applet — AID: `D2 76 00 00 85 01 02`

## SELECT APPLICATION

| Field | Value |
|-------|-------|
| CLA | 00 |
| INS | A4 |
| P1 | 04 |
| P2 | 00 |
| Data | D2 76 00 00 85 01 02 |

## GET_PUBKEY (0x10)

Returns the card's secp256k1 public key (compressed, 33 bytes).

| Field | Value |
|-------|-------|
| CLA | B0 |
| INS | 10 |
| P1 | 00 |
| P2 | 00 |
| Response | 33-byte compressed public key |

## GET_BALANCE (0x11)

Returns the sum of all unspent proof amounts as a 4-byte big-endian uint32 (sats).

## GET_PROOF_COUNT (0x12)

Returns a 1-byte count of total proof slots allocated.

## GET_PROOF (0x13)

Returns proof data at a given index.

| Field | Value |
|-------|-------|
| P1 | Proof index (0-based) |
| Response | 1-byte status (0=unspent, 1=spent) + 8-byte keyset_id + 4-byte amount + 32-byte secret + 33-byte C point |

## SPEND_PROOF (0x20)

Marks proof as spent (irreversible) and returns a NUT-11 P2PK signature.

| Field | Value |
|-------|-------|
| P1 | Proof index |
| Data | 32-byte message to sign (SHA256 of spending condition) |
| Response | 64-byte Schnorr signature |
| Error | 6985 (proof already spent) |

## LOAD_PROOF (0x30)

Stores a new proof. Requires provisioning authentication (session key or admin PIN).

| Field | Value |
|-------|-------|
| Data | 8-byte keyset_id + 4-byte amount + 32-byte secret + 33-byte C point |
| Response | 1-byte slot index assigned |
| Error | 6A84 (no space — all slots used) |

## CLEAR_SPENT (0x31)

Garbage-collects spent proof slots, freeing them for reuse with new proofs (top-up).

| Response | 1-byte count of slots freed |
