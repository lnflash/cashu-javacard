# Security model

What this card protects, what it does not, and which weaknesses are accepted
versus unresolved.

Written to be usable by an auditor. Where something is untested, it says so
rather than asserting a property nobody has measured.

## The one guarantee

**A proof cannot be redeemed without a signature from the card that holds it.**

Proofs are P2PK-locked ([NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md))
to a secp256k1 key generated inside the secure element and never exported. Every
other property below is weaker than this one, and most attacks are attempts to
get around it rather than through it.

## Threat table

| # | Threat | Protected? | Notes |
|---|---|---|---|
| 1 | Passive read of card memory | **Partially** | An attacker gets keyset id, amount, nonce and `C` — the secret string is never stored on the card, but it is reconstructible from the nonce plus the card pubkey, so treat it as leaked too. What does not leak is the private key, so the proofs stay unspendable. Balance and history leak. |
| 2 | Hostile reader spends the card | ❌ **No** | `SPEND_PROOF` needs no PIN. Anyone in NFC range can drain it. See [D12](DECISIONS.md#d12). **Unresolved.** |
| 3 | Card lost or destroyed | ❌ **By design** | No seed, no backup, no recovery. See [D5](DECISIONS.md#d5). |
| 4 | Cloning the chip | **Yes** | Cloning EEPROM copies the proofs but not the key; a clone cannot sign. Cards should be CC EAL 5+ to resist invasive extraction. |
| 5 | Offline double-spend from copied data | ❌ **No** | Fundamental. An offline merchant cannot know a proof was already melted. See below. |
| 6 | Replaying a signature on another proof | **Yes** | The signed message is `sha256(secret)`, unique per proof. A signature does not transfer. |
| 7 | Malicious mint tagging users | **Yes** | NUT-12 DLEQ, verified client-side. See [D11](DECISIONS.md#d11). |
| 8 | Mint insolvency | **Monitored, not prevented** | The mint is trusted for solvency. See below. |
| 9 | Malicious terminal | **Partially** | Cannot forge proofs or spend them elsewhere. Can lie about the amount, or take the tap and never settle — ordinary merchant risk. |
| 10 | Fault injection to recover the key | **Mitigated** | Aux randomness in the nonce prevents the two-signatures-same-`k` recovery. See [D9](DECISIONS.md#d9). |
| 11 | Tear-off during spend | ⚠️ **Unanalysed** | The status write is not in a `JCSystem` transaction. Untested on hardware. |
| 12 | Counterfeit physical cards | **Not a concern** | Value is bound to the chip's key. A look-alike with no valid chip holds nothing. |
| 13 | Supply-chain / pre-personalised cards | ⚠️ **Unaddressed** | Nothing currently attests that a card's key was generated on-card by an untampered applet. |

## The offline double-spend problem (#5)

The card marks a proof `SPENT` before releasing a signature, and no APDU can
unmark it. **That stops the card from spending twice. It does not stop anything
else.**

If an attacker copies a proof's data and separately obtains a signature over it,
they can redeem at the mint while the card still shows the proof unspent — or,
more simply, spend at an offline merchant who cannot check, then redeem the same
proof online before that merchant settles.

**This is inherent to every offline bearer instrument.** Physical cash addresses
it with anti-counterfeiting rather than double-spend detection, and so must this.

Practical mitigations, none of them cryptographic:

- The **mint is the final authority** — the second redemption fails.
- **Terminals should settle promptly** on regaining connectivity. Settlement lag
  is exactly the exposure window.
- **Online terminals must call `checkProofStates`** before accepting. There is
  no excuse when connectivity exists, and `cashu-client` treats `PENDING` as
  not-spendable for the same reason.
- **Keep card balances small.** The loss ceiling is the card balance.

Any claim that this design has "zero double-spend risk" is false. One external
documentation contribution asserted exactly that, which is part of why this
document exists.

## Mint solvency (#8)

A bearer proof is a claim on the mint. If the mint cannot honour it, the proof
is worthless regardless of how sound the cryptography is.

This is not hypothetical here. Flash Forge was found **insolvent** — roughly
$831 of outstanding bearer promises against $0.13 of backing — because the
Lightning backends had been drained while the ecash stayed in circulation.

Current controls:

- **[Public reserves attestation](https://forge.flashapp.me/reserves)**, refreshed
  every 15 minutes, comparing outstanding liability against real backend balances.
- **Automated solvency monitoring** with alerting, per unit.
- The mint's sat reserve is a **self-hosted phoenixd node** rather than a
  third-party custodial account.

Honest limits: this is an **operator attestation**, not a trustless proof of
reserves. A holder cannot cryptographically verify it. Signed attestations from
the reserve wallets would be the next step.

## No PIN on spending (#2)

The sharpest open weakness. `SPEND_PROOF` is deliberately unauthenticated —
possession authorises payment, which is what "bearer" means. The consequence is
that a reader brought within NFC range can drain a card without the holder
noticing.

Profile B+ (PIN-gated spending) is **specified but not implemented**. Note that
any documentation advising users to "set a PIN for high-value cards" is
describing something that does not exist.

Mitigations available today are physical: shielded sleeves, small balances.

This is tracked alongside the existing Flashcard fraud finding (ENG-209) and
should be resolved before volume issuance.

## What has and has not been tested

**Verified in simulation (jCardSim) and by construction:**
- BIP-340 signatures verify against an independent verifier and the spec's own vectors
- Modular arithmetic matches `BigInteger` across random and edge inputs
- Slot lifecycle, PIN gating, APDU encodings
- DLEQ verification, including the tagging attack it exists to catch
- NUT-11 witness checks: wrong key, wrong proof, corrupted signature, `n_sigs`

**Not tested, because no card has run this yet:**
- Any behaviour on physical silicon
- EEPROM wear and lifetime
- Tear-off and power-glitch behaviour
- Timing/side-channel characteristics of the hand-rolled modular arithmetic
- RF range, and whether a drain attack is practical at distance

**Two bugs found in review were invisible to the simulator and would each have
been fatal in the field:** a dropped carry in the modular reduction that made
every signature invalid, and an EEPROM leak that would have bricked cards after
a few hundred taps. Treat simulator results accordingly — see
[D10](DECISIONS.md#d10).

## Open items

1. **PIN-gated spending** (#2) — product decision, blocks volume issuance.
2. **Tear-off analysis** (#11) — needs hardware.
3. **Recovery** (#3) — [PR #4](https://github.com/lnflash/cashu-javacard/pull/4)
   is the live proposal; see [D5](DECISIONS.md#d5) for the flaw to fix first.
4. **Card attestation** (#13) — no proof a key was generated on-card by genuine
   firmware.
5. **Side-channel review** of `SchnorrHW` — the modular arithmetic was written
   for correctness, with no constant-time analysis.
6. **Trustless proof of reserves** — upgrade the attestation to signed
   statements from the reserve wallets.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md). Please do not open a public issue for
anything affecting funds.
