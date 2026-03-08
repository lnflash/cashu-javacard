# NUT-XX: Cashu NFC Card Protocol

`optional`

`depends on: NUT-00, NUT-01, NUT-03, NUT-04, NUT-05, NUT-10, NUT-11`

> **Status: Draft** — Reference implementation at [lnflash/cashu-javacard](https://github.com/lnflash/cashu-javacard). Open for community review.

---

This NUT defines a protocol for storing and spending Cashu `Proof`s on physical NFC cards, enabling offline point-of-sale payments without a persistent internet connection at the time of payment.

Two card profiles are defined to accommodate different chip capabilities and deployment contexts:

- **Profile B** — Bearer (offline): on-card proof storage, hardware secp256k1 signing, internet-optional
- **Profile A** — Reference (online): server-side balance, hardware AES authentication, BoltCard-compatible *(informal — community contributions welcome)*
- **Profile B+** — Bearer with PIN-gated spending: Profile B variant with optional PIN enforcement on `SPEND_PROOF`

This document fully specifies **Profile B** and briefly describes Profile B+ as a variant. Profile A is referenced informally.

---

## Motivation

Cashu ecash tokens are bearer instruments that can be transferred off-chain and offline between parties as byte strings. NFC cards provide a hardware-backed, user-friendly form factor for Cashu: the card stores proofs in tamper-resistant memory and authorizes their spending via an on-chip secp256k1 key, never exposing the private key to the reader.

This enables:

- **Offline point-of-sale payments** in markets with intermittent connectivity
- **Physical bearer instruments** with the usability of a debit card and the privacy of cash
- **Hardware-enforced single-spend** — a proof marked as spent by the card cannot be unmarked, even by an attacker with the card in hand

---

## Definitions

- **Card**: An ISO 14443-4 compliant NFC device running the Cashu card applet (AID: `D2 76 00 00 85 01 02`)
- **Card pubkey** (`P_card`): A secp256k1 public key generated on-device at install time; the corresponding private key never leaves the device
- **Card proof**: A Cashu `Proof` whose `secret` is a NUT-10 `Secret` of kind `P2PK` with `data = hex(P_card)`
- **Reader**: Any NFC-capable application (POS terminal, mobile wallet) that communicates with the card via ISO 7816-4 APDUs
- **Provisioner**: The entity responsible for loading proofs onto the card (typically a POS terminal or wallet connected to the mint)

---

## Profile A — Reference (Online)

| Property | Value |
|----------|-------|
| Tag type | NDEF-capable NFC tag with AES-128 CMAC authentication |
| Balance storage | Server-side (mint or backend) |
| Authentication | Hardware AES-128 CMAC (e.g. SUN message authentication) |
| Connectivity | Online required per payment |
| Double-spend prevention | Server-side |
| Reference | [cashubtc/Numo](https://github.com/cashubtc/Numo) |

Profile A is not formally specified here. The [cashubtc/Numo](https://github.com/cashubtc/Numo) project provides a working Profile A implementation for Android using NDEF tags with CMAC authentication.

> **Community contribution welcome**: A formal Profile A spec (AES CMAC authentication flow, server-side balance API, LNURL-withdraw compatibility) would be a valuable addition. If you are implementing Profile A and want to contribute a spec, please open a PR or discussion.

---

## Profile B — Bearer (Offline)

### Card Requirements

| Property | Value |
|----------|-------|
| Interface | ISO 14443-4 (NFC Type A/B), ISO 7816-4 APDU transport |
| Cryptography | secp256k1 key-pair generation; BIP-340 Schnorr signing |
| Persistent storage | ≥ 8 KB non-volatile (2,496 bytes proof storage + OS overhead) |
| AID | `D2 76 00 00 85 01 02` |

> **Note**: Any ISO 7816-4 compliant NFC device capable of secp256k1 key generation and Schnorr signing may implement Profile B. Example chips known to meet these requirements: NXP JCOP4 SmartMX3 (CC EAL 5+), Feitian JavaCard 3.0.4+.

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

### Concrete Example

Given:
- Card pubkey (`P_card`): `02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2`
- Nonce (`x`): `916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e`
- Keyset ID: `0059534ce0bfa19a` (8 bytes binary: `00 59 53 4c e0 bf a1 9a`)
- Amount: `8` sats
- Mint signature (`C`): `024a43eddcf0e42dad32ca5c0e82e51d7a38e7a48b80e89d2e17cc94abb02c04c3`

The reconstructed `Proof.secret` is the following string (key order and no spaces are mandatory):

```
["P2PK",{"nonce":"916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e","data":"02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2","tags":[["sigflag","SIG_INPUTS"]]}]
```

The message sent to `SPEND_PROOF` is:

```
msg = SHA256("["P2PK",{"nonce":"916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e","data":"02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2","tags":[["sigflag","SIG_INPUTS"]]}]")
    = SHA256(UTF8(Proof.secret))
```

After calling `SPEND_PROOF`, the reader assembles the full proof for mint redemption:

```json
{
  "id": "0059534ce0bfa19a",
  "amount": 8,
  "secret": "[\"P2PK\",{\"nonce\":\"916c21b8c67da71e9d02f4e3adc6f30700c152e01a07ae30e3bcc6b55b0c9e5e\",\"data\":\"02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2\",\"tags\":[[\"sigflag\",\"SIG_INPUTS\"]]}]",
  "C": "024a43eddcf0e42dad32ca5c0e82e51d7a38e7a48b80e89d2e17cc94abb02c04c3",
  "witness": "{\"signatures\":[\"<64-byte Schnorr signature from card hex-encoded>\"]}"
}
```

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

The 64-byte response is a [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) Schnorr signature:

```
[R_x (32 bytes)] [s (32 bytes)]
```

Signing algorithm (BIP-340):

1. Let `d` = card private key scalar; `P` = `d * G`
2. If `P.y` is odd, let `d' = n - d`, else `d' = d`
3. Let `k` = `tagged_hash("BIP0340/nonce", d' || zeros32 || msg) mod n`
4. Let `R = k * G`; if `R.y` is odd, let `k = n - k`
5. Let `e = tagged_hash("BIP0340/challenge", bytes(R.x) || bytes(P.x) || msg) mod n`
6. Let `s = (k + e * d') mod n`
7. Return `bytes(R.x) || bytes(s)`

where `tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)`.

This is compatible with standard BIP-340 verification and NUT-11 P2PK signature verification.

---

## Profile B+ — Bearer with PIN-Gated Spending

Profile B+ is a variant of Profile B in which `SPEND_PROOF` requires a valid PIN to have been presented in the current NFC session (via `VERIFY_PIN`) before the card will authorize a spend.

This variant is suitable for higher-value cards where the issuer or user wants an additional factor beyond physical possession.

**Changes from Profile B:**

- `SPEND_PROOF` checks `pinVerifiedFlag` before signing; returns `6982 (SECURITY STATUS NOT SATISFIED)` if PIN not verified
- Reader flow adds `VERIFY_PIN` step before Step 4 in the payment flow
- Card MUST have a PIN set (`SET_PIN` called during provisioning)

**Advertising Profile B+:**

Cards running Profile B+ SHOULD set a capability flag in the `GET_INFO` response indicating PIN-gated spending is enforced. Readers MUST check this flag and prompt the user for their PIN before attempting `SPEND_PROOF`.

**NUT scope:** Profile B+ is not formally specified in this NUT. Implementors are encouraged to propose a Profile B+ amendment or separate NUT once the base Profile B implementation is stable.

---

## Security Model

### Threat: Physical card theft

**Risk**: An attacker who steals the card can spend all proofs.

**Mitigation**: This is equivalent risk to physical cash. Card balance should reflect the user's risk tolerance (analogous to wallet cash). Optional PIN (`VERIFY_PIN`) can be enabled for high-value cards but is NOT required for spending in the base profile (bearer semantics).

### Threat: Card cloning / EEPROM extraction

**Risk**: A sophisticated attacker with chip-level access and invasive probing equipment could extract proof data from EEPROM before spend.

**Mitigation**:
- Cards certified to CC EAL 5+ or higher provide hardware protection against invasive attacks
- The card private key is generated on-device, stored in secure non-volatile memory, and never exported — cloning the EEPROM gives the attacker the proof secrets but NOT the card key. Proofs without a valid P2PK signature are rejected by the mint.
- For high-value cards, implementors SHOULD use devices with formal tamper-resistance certification

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

1. **Profile A formal spec**: Profile A (NTAG 424 / server-side balance) is informally referenced in this NUT. A full Profile A spec is deferred — community contributions welcome (see Profile A section above).

2. **Denomination scheme**: The NUT currently recommends (SHOULD) power-of-2 denominations. Should this be stronger (MUST)? Or is denomination selection best left entirely to the provisioner?

3. **Key derivation for recovery**: Should card keypairs be derivable from a BIP-39 seed for recovery? Currently, a lost or damaged card means lost funds — same as physical cash. Derivable keys would allow card replacement at the cost of requiring the user to manage a seed.

4. **Multiple mints / keysets**: Should a single card support proofs from multiple mints simultaneously? The current design stores keyset IDs per proof, which technically allows it, but there is no discovery mechanism defined.

5. **Proof encoding standard**: Should the compact binary slot format (78 bytes) be formalized as a CBOR or TLV encoding, or remain an opaque implementation detail of the APDU interface?

---

## Appendix: Profile Comparison

| Property | Profile A | Profile B |
|----------|-----------|-----------|
| Device type | NDEF tag with AES-128 CMAC | ISO 7816-4 smart card with secp256k1 |
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
- [NXP JCOP4 SmartMX3](https://www.nxp.com/products/security-and-authentication/secure-service-2go/jcop-4): Example Profile B chip (CC EAL 5+)
- [Feitian JavaCard 3.0.4+](https://www.ftsafe.com/Products/Java_Card): Example Profile B chip
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki): Schnorr signatures

[00]: https://github.com/cashubtc/nuts/blob/main/00.md
[01]: https://github.com/cashubtc/nuts/blob/main/01.md
[03]: https://github.com/cashubtc/nuts/blob/main/03.md
[04]: https://github.com/cashubtc/nuts/blob/main/04.md
[05]: https://github.com/cashubtc/nuts/blob/main/05.md
[06]: https://github.com/cashubtc/nuts/blob/main/06.md
[10]: https://github.com/cashubtc/nuts/blob/main/10.md
[11]: https://github.com/cashubtc/nuts/blob/main/11.md
