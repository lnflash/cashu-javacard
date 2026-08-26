# Architecture

How the pieces fit together, what each is responsible for, and — stated
explicitly — which parts do not exist yet.

For *why* it is shaped this way, read [`VISION.md`](VISION.md) first. For the
specific engineering calls, [`DECISIONS.md`](DECISIONS.md).

## The system

Five components across four repositories plus a running mint:

| Component | Repo | Language | Status |
|---|---|---|---|
| **Applet** — the card firmware | [`cashu-javacard`](https://github.com/lnflash/cashu-javacard) `applet/` | JavaCard | Builds, CI green, **never run on hardware** |
| **cardctl** — host driver | [`cashu-javacard`](https://github.com/lnflash/cashu-javacard) `tools/cardctl/` | Python | Works; untested against a real card |
| **cashu-client** — mint protocol | [`cashu-client`](https://github.com/lnflash/cashu-client) | TypeScript | Load + redeem implemented |
| **Card artwork** — physical design | [`flash-card-assets`](https://github.com/lnflash/flash-card-assets) | SVG/PDF | Draft v1, not released to plate |
| **Flash Forge** — the mint | `forge.flashapp.me` | Nutshell (Python) | **Live, solvent, in production** |
| **Merchant terminal** | — | — | ❌ **Does not exist** |

That last row is the honest gap. `flash-pos` contains no Cashu code. Until a
terminal exists, the card can be loaded and read but not spent in the field.

## Trust boundaries

This is the diagram that matters most, because almost every design decision
follows from where these lines sit.

```
┌──────────────────────────────────────────────────────────────┐
│ THE MINT (forge.flashapp.me)                                 │
│  · issues proofs, honours redemptions, holds the reserve     │
│  · is the ONLY authority on whether a proof is still unspent │
│  · trusted for solvency; NOT trusted for unlinkability       │
│    (that is what NUT-12 DLEQ checks)                         │
└──────────────────────────────────────────────────────────────┘
            ▲                                    ▲
   issue    │                                    │  redeem (melt)
            │                                    │
┌───────────┴────────────┐          ┌────────────┴───────────────┐
│ PROVISIONING HOST      │          │ MERCHANT TERMINAL          │
│  · does the BDHKE math │          │  · reads proofs off card   │
│  · knows blinding r    │          │  · asks card to sign       │
│  · loads proofs        │          │  · submits melt to mint    │
│  · NOT trusted by card │          │  · NOT trusted by card     │
└───────────┬────────────┘          └────────────┬───────────────┘
            │ APDU                               │ APDU
            ▼                                    ▼
┌──────────────────────────────────────────────────────────────┐
│ THE CARD                                                     │
│  · holds proofs + a secp256k1 key that NEVER leaves          │
│  · signs a 32-byte message on request                        │
│  · marks a slot SPENT before releasing the signature         │
│  · trusts nobody: it authorises, it does not authenticate    │
└──────────────────────────────────────────────────────────────┘
```

**The card trusts no one.** It does not verify that a terminal is a real
merchant, that a message is a real payment, or that a proof it is handed is
genuine. It does exactly one security-relevant thing: it will not produce a
second signature for a slot it has already marked spent.

**The terminal is not trusted either** — by anyone. It cannot forge proofs (it
lacks the mint's key) and it cannot spend a card's proofs elsewhere (they are
P2PK-locked to the card). It *can* refuse to settle, or lie to the customer
about the amount, which is ordinary merchant risk.

**The mint is trusted for solvency and nothing else.** It could try to tag users
by signing with per-user keys — [NUT-12 DLEQ](https://github.com/cashubtc/nuts/blob/main/12.md)
detects that, and `cashu-client` verifies it. It could become insolvent — which
is why [the reserve is monitored publicly](https://forge.flashapp.me/reserves).

## Division of labour: why the card does so little

The card **does not** do BDHKE. It never blinds, never unblinds, never talks to
a mint, and never sees a blinding factor. It stores proofs and it signs.

That is deliberate. JavaCard has no big-integer arithmetic, no `long`, and no
garbage collector; every byte of scratch space must be allocated once at install
time. Implementing blinding on-card would multiply the applet's size and its
attack surface to buy nothing — the blinding math is not secret and the host is
already the party that must know `r` in order to unblind.

So the split is:

| Concern | Where |
|---|---|
| Blinding, unblinding, denomination splitting | `cashu-client` (host) |
| Mint HTTP: quotes, mint, melt, swap, checkstate | `cashu-client` (host) |
| DLEQ verification | `cashu-client` (host) |
| Proof storage, slot lifecycle | **Applet** |
| The private key, and BIP-340 signing | **Applet** |
| Single-spend enforcement (on-card) | **Applet** |
| APDU transport | `cardctl` (host) |

The card holds the one thing that cannot live anywhere else: **a private key
that has never existed outside the secure element.**

## On-card data model

Each proof occupies exactly 78 bytes of EEPROM:

```
Offset  Size  Field
0       1     status (0=empty, 1=unspent, 2=spent)
1       8     keyset_id (8 ASCII bytes of the hex keyset id)
9       4     amount (uint32, big-endian, in the keyset's base unit)
13      32    secret (the NUT-10 P2PK secret string's bytes)
45      33    C (compressed secp256k1 point — the mint's unblinded signature)
```

32 slots × 78 bytes = **2,496 bytes** of proof storage, plus the EC keypair and
applet code. The `amount` unit follows the keyset — sats for a `sat` keyset,
cents for `usd`.

`MAX_PROOFS = 32` is a real constraint on the product, not just the code: a
Cashu balance is split into powers of two, so 32 slots comfortably holds a
useful balance but is not unlimited. `cashu-client`'s `splitIntoDenominations`
takes a `maxSlots` argument for exactly this reason.

## Key management

- The card keypair is generated **at install time**, on-card, via
  `KeyPair.genKeyPair()`.
- The private key lives in JavaCard's protected key storage — never in a
  `byte[]`, never exported, no APDU returns it.
- `GET_PUBKEY` returns the 33-byte compressed public key. That is the card's
  identity and the key proofs are locked to.
- For [NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md), the
  provisioning host puts this key in each proof's P2PK secret, so the mint will
  only redeem those proofs against a signature from this card.

**Consequence:** a card is unrecoverable by design. There is no seed, no backup,
no derivation path. Destroy the card and the key is gone, and with it any proofs
locked to it. See [`DECISIONS.md`](DECISIONS.md#d5) for why BIP-39 was rejected
and what the open alternative is.

## Spend protection

`SPEND_PROOF` writes `STATUS_SPENT` to the slot **before** it signs. No APDU can
reset a slot to unspent — the command does not exist. `CLEAR_SPENT` zeroes
already-spent slots to reclaim space; it does not undo a spend.

Two honest caveats:

1. **This is a status byte, not a counter.** Earlier documentation called it a
   "non-resettable hardware spend counter", which overstates it.
2. **Tear-off behaviour is unanalysed.** The write is not wrapped in a
   `JCSystem` transaction, so what happens if the card is pulled from the field
   between the status write and the signature has not been characterised on
   hardware. Flagged in [`SECURITY-MODEL.md`](SECURITY-MODEL.md).

## The two flows

### Loading a card (online)

```
1. cashu-client: requestMintQuote(mint, amount, unit)     → bolt11 invoice
2. (pay the invoice by any means)
3. cashu-client: splitIntoDenominations(amount, maxSlots) → [64, 16, 4, …]
4. cashu-client: createBlindedMessage(keysetId, amt, cardPubkey)
                 ↳ builds the NUT-10 P2PK secret locked to the CARD's key
5. cashu-client: mintProofs(...)                          → blind signatures
6. cashu-client: unblindSignature(...) + proofDLEQFromBlindSignature(...)
7. cashu-client: verifyProofDLEQ(...)                     → offline check
8. cardctl:      LOAD_PROOF × n                           → written to slots
```

Step 4 is the pivot: the host locks each proof to a key it does not control.
From that moment the proof is only spendable by that card.

### Spending at a terminal

```
1. terminal: GET_SLOT_STATUS / GET_PROOF          → read proofs off the card
2. cashu-client: requestMeltQuote(mint, invoice)  → amount + fee reserve
3. cashu-client: selectProofsForMelt(...)         → minimal covering set
4. cashu-client: p2pkMessageToSign(proof)         → sha256(secret)
5. card:     SPEND_PROOF(slot, message)           → marks SPENT, returns 64-byte sig
6. cashu-client: attachP2PKWitness(proof, [sig])  → NUT-11 witness
7. cashu-client: meltProofs(...)                  → mint pays the invoice
```

Steps 5 and 6 are the whole reason the card exists: the signature that unlocks
the proof can only be produced by the chip.

Note the ordering hazard — **the card burns its slot at step 5, before the mint
has accepted anything at step 7.** That asymmetry is why `cashu-client` refuses
locally rather than optimistically submitting; see
[`DECISIONS.md`](DECISIONS.md#d7).

## Hardware floor

**JavaCard 3.0.5 or later.** Not a preference — the Schnorr signer computes
`k·G` with `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, a constant that **does not
exist in the 3.0.4 API**. Verified directly against the SDK jars. JCOP3, J3H145
and Feitian 3.0.4 parts cannot run this applet at all.

The card must also be **dual-interface** (contactless ISO/IEC 14443-4 for taps,
contact ISO/IEC 7816 for reliable applet loading) and supplied **unlocked**, with
known GlobalPlatform keys, or the applet can never be installed.

## Where to go next

| You want to… | Read |
|---|---|
| Understand a specific design call | [`DECISIONS.md`](DECISIONS.md) |
| Know what an attacker can do | [`SECURITY-MODEL.md`](SECURITY-MODEL.md) |
| Talk to a card | [`../tools/cardctl/README.md`](../tools/cardctl/README.md) |
| Load the applet onto silicon | [`HARDWARE_DEPLOYMENT.md`](HARDWARE_DEPLOYMENT.md) |
| Read the wire protocol | [`../spec/APDU.md`](../spec/APDU.md) |
| Read the protocol spec | [`../spec/NUT-XX.md`](../spec/NUT-XX.md) |
| Look up a term | [`GLOSSARY.md`](GLOSSARY.md) |
