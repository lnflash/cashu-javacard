# NUT-XX: Cashu NFC Card Protocol

`optional`

`depends on: NUT-00, NUT-01, NUT-03, NUT-04, NUT-05, NUT-10, NUT-11`

> **Status: Draft** — Reference implementation in progress at [lnflash/cashu-javacard](https://github.com/lnflash/cashu-javacard). Targeting submission to cashubtc/nuts after reference implementation is complete.

---

This NUT defines a protocol for storing and spending Cashu `Proof`s on physical NFC cards, enabling offline point-of-sale payments without a persistent internet connection at the time of payment.

Two card profiles are defined to accommodate different chip capabilities and deployment contexts:

- **Profile A** — Reference (online): server-side balance, hardware AES authentication, BoltCard-compatible
- **Profile B** — Bearer (offline): on-card proof storage, hardware secp256k1 signing, internet-optional

This document specifies **Profile B**. Profile A is referenced informally for completeness.

---

## Motivation

Cashu ecash tokens are bearer instruments that can be transferred off-chain and offline between parties as byte strings. NFC cards provide a hardware-backed, user-friendly form factor for Cashu: the card stores proofs in tamper-resistant memory and authorizes their spending via an on-chip secp256k1 key, never exposing the private key to the reader.

This enables:

- **Offline point-of-sale payments** in markets with intermittent connectivity
- **Physical bearer instruments** with the usability of a debit card and the privacy of cash
- **Hardware-enforced single-spend** — a proof marked as spent by the card cannot be unmarked, even by an attacker with the card in hand

---

## Definitions

- **Card**: A JavaCard 3.0.4+ NFC smartcard running the Cashu applet (AID: `D2 76 00 00 85 01 02`)
- **Card pubkey** (`P_card`): A secp256k1 public key generated on-chip at install time; the corresponding private key never leaves the card
- **Card proof**: A Cashu `Proof` whose `secret` is a NUT-10 `Secret` of kind `P2PK` with `data = hex(P_card)`
- **Reader**: Any NFC-capable application (POS terminal, mobile wallet) that communicates with the card
- **Provisioner**: The entity responsible for loading proofs onto the card (typically a POS terminal or wallet connected to the mint)

---

## Profile A — Reference (Online)

| Property | Value |
|----------|-------|
| Chip | NTAG 424 DNA or equivalent (AES-128 CMAC) |
| Balance storage | Server-side (mint or backend) |
| Authentication | Hardware AES CMAC (SUN message authentication) |
| Connectivity | Online required per payment |
| Double-spend prevention | Server-side |
| Reference | [cashubtc/Numo](https://github.com/cashubtc/Numo) |

Profile A is not further specified here. See [cashubtc/Numo](https://github.com/cashubtc/Numo) for the reference implementation.

---

## Profile B — Bearer (Offline)

### Card Requirements

| Property | Value |
|----------|-------|
| Chip | JavaCard 3.0.4+ with secp256k1 EC-FP support |
| Examples | Feitian JavaCard 3.0.4+, NXP JCOP4 SmartMX3 |
| EEPROM | ≥ 8 KB (2,496 bytes proof storage + OS overhead) |
| AID | `D2 76 00 00 85 01 02` |
| Interface | ISO 14443-4 (NFC Type A/B) |

### Proof Format on Card

Card proofs are Cashu `Proof`s locked with a NUT-11 P2PK spending condition to the card's public key. When loaded onto the card, they are stored in a compact binary format.

**Binary proof slot (78 bytes):**

```
Offset  Len  Field        Description
------  ---  -----        -----------
0       1    status       0x00=empty, 0x01=unspent, 0x02=spent
1       8    keyset_id    Binary keyset ID (8 bytes = 16 hex chars of NUT-01 keyset ID)
9       4    amount       Big-endian uint32, in keyset's base unit (sats or cents)
13      32   nonce        The 32-byte random nonce from the P2PK Secret
45      33   C            Compressed secp256k1 mint signature point
```

**Maximum slots**: 32 (configurable at install time, limited by available EEPROM)

**Reconstructing the full Proof from card storage:**

Given the stored fields and the card's public key (`P_card` from `GET_PUBKEY`), a reader reconstructs the full `Proof` as follows:

```python
# Reconstruct Proof.secret (NUT-10 well-known secret of kind P2PK)
secret = json.dumps([
    "P2PK",
    {
        "nonce": nonce.hex(),
        "data": P_card.compressed_hex(),
        "tags": [["sigflag", "SIG_INPUTS"]]
    }
], separators=(",", ":"))

# Reconstruct Proof
proof = {
    "id":     keyset_id.hex(),
    "amount": amount,
    "secret": secret,
    "C":      C.compressed_hex()
}
```

The `secret` JSON MUST be serialized **without spaces** and with keys in the order shown above to ensure a consistent serialization for signing.

---

## Card Provisioning

Provisioning loads signed Cashu proofs onto the card. Proofs MUST be locked to the card's public key using NUT-11 P2PK spending conditions before loading.

### Step 1 — Discover Card Pubkey

```
Reader  -->  Card: SELECT APPLICATION (AID: D2 76 00 00 85 01 02)
Reader  -->  Card: GET_PUBKEY (INS: 0x10)
Card    -->  Reader: P_card (33-byte compressed secp256k1 public key)
```

### Step 2 — Mint Locked Proofs

The reader (or a connected backend) requests proofs from the mint that are locked to `P_card`:

**Blind message construction (NUT-03):**

For each desired denomination, generate a nonce `x` (32 random bytes) and construct the P2PK secret:

```json
["P2PK", {
  "nonce": "<hex(x)>",
  "data": "<hex(P_card)>",
  "tags": [["sigflag", "SIG_INPUTS"]]
}]
```

Serialize this JSON (no spaces) and use it as the secret for blind signature request per NUT-03/NUT-04.

**Denomination selection**: Proofs SHOULD follow standard Cashu power-of-2 denominations to enable exact-amount payment selection. The provisioner splits the desired total into an optimal denomination set.

### Step 3 — Write Proofs to Card

For each proof received from the mint, write it to the card:

```
Reader  -->  Card: VERIFY_PIN (if PIN is set; required for LOAD_PROOF)
Reader  -->  Card: CLEAR_SPENT (reclaim any spent slots)
Reader  -->  Card: LOAD_PROOF [keyset_id(8) || amount(4) || nonce(32) || C(33)]
Card    -->  Reader: slot_index (1 byte)
```

Repeat `LOAD_PROOF` for each proof. After all proofs are loaded, verify:

```
Reader  -->  Card: GET_BALANCE
Card    -->  Reader: total unspent balance (uint32)
```

---

## Payment Flow

### Offline Payment

Payment requires no internet connection at the time of the transaction. The merchant stores the signed proofs locally and redeems them when connectivity is available.

```
Step 1: Tap

  Customer taps card at merchant terminal.

Step 2: Enumerate available proofs

  Reader --> Card: GET_BALANCE
  Reader <-- Card: balance (uint32)

  if balance < payment_amount:
      abort: "Insufficient balance"

  Reader --> Card: GET_SLOT_STATUS
  Reader <-- Card: 32-byte array (one status byte per slot)

Step 3: Select proofs

  Reader reads unspent proofs to find a subset summing to >= payment_amount.
  Prefer exact match; otherwise select minimum overpayment.

  For each candidate slot idx:
      Reader --> Card: GET_PROOF (P1=idx)
      Reader <-- Card: proof data (78 bytes)
      Reconstruct full Proof from stored data + P_card (see above)

Step 4: Spend proofs (ATOMIC PER PROOF)

  For each selected proof at slot idx:
      msg = SHA256(UTF8(proof.secret))   # 32-byte message to sign
      Reader --> Card: SPEND_PROOF (P1=idx, Data=msg[32])
      Card: marks slot as STATUS_SPENT (IRREVERSIBLE)
      Card: signs msg with card private key (Schnorr)
      Reader <-- Card: signature (64 bytes: R_x[32] || s[32])

      Attach signature to proof:
          proof.witness = {"signatures": [signature.hex()]}

Step 5: Confirm to customer

  Reader displays: "Payment accepted — X sats"
  (No internet required at this point)

Step 6: Settle (online, deferred)

  When connectivity is available, merchant redeems proofs with mint:
      POST /v1/melt (NUT-05) with the collected proofs
  OR
      POST /v1/swap (NUT-03) to exchange for fresh proofs
```

### Signature Verification

The NUT-11 P2PK signature produced in Step 4 can be verified by the mint during redemption. Verification follows standard NUT-11 rules:

1. Parse `Proof.secret` as a NUT-10 `Secret` of kind `P2PK`
2. Extract the signing public key from `Secret.data` (`P_card`)
3. Verify the Schnorr signature in `Proof.witness.signatures[0]` on `SHA256(UTF8(Proof.secret))` with `P_card`

The mint enforces this condition when `SIG_INPUTS` is set, ensuring only the card can authorize spending.

### Offline Proof Validity Check

A merchant may optionally verify proof validity offline without contacting the mint, using the mint's published public keys (NUT-01):

1. Retrieve the mint keyset for `Proof.id` (cached from a prior online session)
2. Verify the mint signature: `C == k_amount * hash_to_curve(Proof.secret)` where `k_amount` is the mint's public key for the proof's amount
3. Verify the P2PK signature (see above)

This offline check provides strong assurance that the proof was legitimately issued by the mint and authorized by this specific card. It does not prevent double-spend from a cloned card.

---

## Denomination Handling and Change

### Proof Selection

To pay exactly `amount` sats, the reader selects a minimal subset of unspent proofs whose sum equals `amount`. If no exact match is possible, the reader selects proofs summing to the smallest value greater than `amount`.

**Overpayment**: If selected proofs sum to more than `amount`, the excess is merchant income. Cards SHOULD be pre-loaded with power-of-2 denominations (1, 2, 4, 8, 16, ...) to minimize overpayment.

**Change to card**: Returning change to the card is NOT performed during the offline payment step. Change may optionally be credited to the card in a subsequent online provisioning session (i.e., the merchant's backend creates new proofs for the change amount and loads them onto the card during the next tap).

---

## APDU Interface

Card communication uses ISO 7816-4 APDUs. All commands use `CLA = B0`.

### Required Commands

| INS | Name | Description |
|-----|------|-------------|
| 0x10 | `GET_PUBKEY` | Returns 33-byte compressed card public key |
| 0x11 | `GET_BALANCE` | Returns uint32 sum of unspent proof amounts |
| 0x13 | `GET_PROOF` | Returns 78-byte proof slot data at given index |
| 0x14 | `GET_SLOT_STATUS` | Returns 32-byte status array (one byte per slot) |
| 0x20 | `SPEND_PROOF` | Marks proof spent and returns 64-byte Schnorr signature |
| 0x30 | `LOAD_PROOF` | Writes a proof into the next empty slot |

See [`APDU.md`](APDU.md) for complete command reference including optional commands.

### SELECT Response

Upon successful SELECT, the card returns a 2-byte version indicator:

```
[major_version (1 byte)] [minor_version (1 byte)]
```

### SPEND_PROOF — Message Construction

The 32-byte message sent to `SPEND_PROOF` MUST be:

```
msg = SHA256(UTF8(Proof.secret))
```

where `Proof.secret` is the serialized P2PK secret string (no spaces, deterministic key order).

### SPEND_PROOF — Signature Format

The 64-byte response is a BIP-340 Schnorr signature:

```
[R_x (32 bytes)] [s (32 bytes)]
```

where:
- `k` = deterministic nonce (RFC 6979 or on-chip RNG)
- `R = k * G`
- `e = SHA256(bytes(R_x) || bytes(P_card) || msg)`
- `s = (k - e * privkey) mod n`

This is compatible with NUT-11 P2PK signature verification.

---

## Security Model

### Threat: Physical card theft

**Risk**: An attacker who steals the card can spend all proofs.

**Mitigation**: This is equivalent risk to physical cash. Card balance should reflect the user's risk tolerance (analogous to wallet cash). Optional PIN (`VERIFY_PIN`) can be enabled for high-value cards but is NOT required for spending in the base profile (bearer semantics).

### Threat: Card cloning / EEPROM extraction

**Risk**: A sophisticated attacker with chip-level access and invasive probing equipment could extract proof data from EEPROM before spend.

**Mitigation**: 
- JCOP4 (CC EAL 5+) provides hardware protection against invasive attacks
- Card private key is generated on-chip, stored in secure memory, and never exported — cloning the EEPROM gives the attacker the proof secrets but NOT the card key. They can attempt to redeem proofs without the P2PK signature, but the mint rejects these if P2PK is enforced.
- For high-value cards, use chips with higher security certification

### Threat: Offline double-spend window

**Risk**: Between the card being tapped and the merchant settling online, an attacker could attempt to spend the same proof at another terminal (if they have a cloned card or can intercept the settlement).

**Mitigation**:
- The card's STATUS_SPENT flag is set BEFORE the signature is returned in `SPEND_PROOF`. This is atomic and irreversible at the hardware level.
- Mint enforces P2PK signature requirement, so a proof without the card signature is rejected
- Merchants should set short settlement windows for high-value transactions

### Threat: Malicious provisioner loading fake proofs

**Risk**: A provisioner could attempt to load proofs that were not actually issued by the mint (fabricated C values).

**Mitigation**: 
- The card does not validate proofs at load time (it has no mint pubkey)
- Proof validity is enforced by the mint at redemption time
- Users should only provision from trusted sources (their own wallet or the Flash app)
- PIN protection on `LOAD_PROOF` ensures only authorized provisioners can write to the card

### Threat: Replay attack on SPEND_PROOF

**Risk**: A reader captures a `SPEND_PROOF` signature and replays it.

**Mitigation**: The signature is over `SHA256(Proof.secret)` which is unique per proof (includes the unique nonce). A replayed signature is for the same proof, which will be rejected by the mint as already seen (standard Cashu double-spend prevention).

---

## Mint Support

Mints supporting NUT-XX cards MUST:

1. Support NUT-11 P2PK spending conditions (`SIG_INPUTS`)
2. Accept P2PK-locked proofs during melt (NUT-05) and swap (NUT-03)
3. Verify Schnorr signatures over `SHA256(UTF8(Proof.secret))`

Mints SHOULD advertise NUT-XX support in their info endpoint (NUT-06):

```json
{
  "nuts": {
    "XX": {
      "supported": true,
      "profiles": ["A", "B"]
    }
  }
}
```

---

## Wallet / POS Integration

Wallets or POS applications implementing NUT-XX MUST:

1. Cache the card's pubkey (`P_card`) after the first `GET_PUBKEY` call in a session
2. Reconstruct `Proof.secret` from stored `nonce` and `P_card` before signing
3. Compute `msg = SHA256(UTF8(Proof.secret))` before calling `SPEND_PROOF`
4. Attach the returned signature as `proof.witness.signatures[0]` (hex-encoded)
5. Store collected `(proof, witness)` pairs durably before confirming payment to user
6. Settle with the mint within a reasonable time window

---

## AID Assignment

`D2 76 00 00 85 01 02`

| Bytes | Meaning |
|-------|---------|
| `D2 76 00 00 85` | NFC Forum registered AID prefix for non-NFC Forum applications |
| `01` | Cashu protocol identifier |
| `02` | Profile B (Bearer) |

---

## Open Questions

The following design questions are open for community discussion:

1. **Profile A formal spec**: Should Profile A (NTAG 424 / server-side balance) be specified in this NUT or a separate NUT?

2. **Denomination scheme**: Should the NUT mandate power-of-2 denominations for card proofs, or leave denomination selection to the provisioner?

3. **Change handling**: Should a formal change-return protocol be specified (e.g., the merchant returns change proofs to the card via a follow-up LOAD_PROOF session)?

4. **Key derivation for recovery**: Should card keypairs be derivable from a BIP-39 seed for card recovery? (Currently, loss of card = loss of funds for bearer cards.)

5. **Multiple keysets**: Should a single card support proofs from multiple mints / keysets simultaneously?

6. **PIN semantics**: Should PIN protection for `SPEND_PROOF` be an optional profile variant (Profile B+)?

7. **Proof encoding**: Should the compact binary slot format be a formal encoding standard, or left to implementation?

---

## Appendix: Profile Comparison

| Property | Profile A | Profile B |
|----------|-----------|-----------|
| Chip | NTAG 424 DNA | JavaCard 3.0.4+ |
| Approx. cost | $0.50–1.00/card | $1.50–8.00/card |
| Balance storage | Server-side | On-card EEPROM |
| Internet at payment | Required | Optional (offline) |
| EC keypair on card | No | Yes (secp256k1) |
| Custom applet | No | Yes (open source) |
| Double-spend prevention | Server | Hardware + Mint |
| BoltCard compatible | Yes | No |
| Privacy | Server knows balance | Card knows balance |
| Recommended use | Urban / always-online | Rural / offline markets |

---

## References

- [NUT-00][00]: Notation and models
- [NUT-01][01]: Mint public keys
- [NUT-03][03]: Swap
- [NUT-04][04]: Mint tokens
- [NUT-05][05]: Melting tokens
- [NUT-06][06]: Mint info
- [NUT-10][10]: Spending conditions
- [NUT-11][11]: Pay to Public Key (P2PK)
- [cashubtc/Numo](https://github.com/cashubtc/Numo): Android Cashu NFC POS (Profile A reference)
- [lnflash/cashu-javacard](https://github.com/lnflash/cashu-javacard): Profile B reference implementation
- [NXP JCOP4 SmartMX3](https://www.nxp.com/products/security-and-authentication/secure-service-2go/jcop-4): Recommended chip (CC EAL 5+)
- [Feitian JavaCard](https://www.ftsafe.com/Products/Java_Card): Alternative chip (JavaCard 3.0.4+)
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki): Schnorr signatures

[00]: https://github.com/cashubtc/nuts/blob/main/00.md
[01]: https://github.com/cashubtc/nuts/blob/main/01.md
[03]: https://github.com/cashubtc/nuts/blob/main/03.md
[04]: https://github.com/cashubtc/nuts/blob/main/04.md
[05]: https://github.com/cashubtc/nuts/blob/main/05.md
[06]: https://github.com/cashubtc/nuts/blob/main/06.md
[10]: https://github.com/cashubtc/nuts/blob/main/10.md
[11]: https://github.com/cashubtc/nuts/blob/main/11.md
