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
| 2 | Hostile reader spends the card | **Once a PIN is set** | `SPEND_PROOF` and `SIGN_ARBITRARY` are gated on `VERIFY_PIN` in the same session (D13), and a failed PIN check ends that session. A card with no PIN set — the factory state — can be drained by anyone in NFC range, so the holder must set one before carrying value. Three wrong tries block the card; the gate keeps refusing in the blocked state (ENG-615 closed a bug where it stopped), and there is no unblock path (D13). That dead end is its own threat: see #14. |
| 3 | Card lost or destroyed | ❌ **By design** | No seed, no backup, no recovery. See [D5](DECISIONS.md#d5). |
| 4 | Cloning the chip | **Yes** | Cloning EEPROM copies the proofs but not the key; a clone cannot sign. Cards should be CC EAL 5+ to resist invasive extraction. |
| 5 | Offline double-spend from copied data | ❌ **No** | Fundamental. An offline merchant cannot know a proof was already melted. See below. |
| 6 | Replaying a signature on another proof | **Yes** | The signed message is `sha256(secret)`, unique per proof. A signature does not transfer. |
| 7 | Malicious mint tagging users | **Yes** | NUT-12 DLEQ, verified client-side. See [D11](DECISIONS.md#d11). |
| 8 | Mint insolvency | **Monitored, not prevented** | The mint is trusted for solvency. See below. |
| 9 | Malicious terminal | **Partially** | Cannot forge proofs or spend them elsewhere. Can lie about the amount, or take the tap and never settle — ordinary merchant risk. |
| 10 | Fault injection to recover the key | **Mitigated** | Aux randomness in the nonce prevents the two-signatures-same-`k` recovery. See [D9](DECISIONS.md#d9). |
| 11 | Tear-off (card pulled mid-write) | **Yes, by write order** (applet 0.4 on); not yet on silicon | Every slot write changes the data first and commits the status byte last, as a single byte the JCRE writes atomically ([D14](DECISIONS.md#d14)). A card whose `SELECT` answers below `00 04` may write the status byte first and needs the CAP reinstalled. A torn `LOAD_PROOF` leaves the slot empty and a torn `CLEAR_SPENT` leaves it spent; neither state is counted in the balance or signed for. The empty slot's bytes are never read. The half-cleared spent slot still answers `GET_PROOF`, as status `02` with some fields zeroed, and its data is not a proof: a reader that uses a spent slot's data must check it ([`spec/APDU.md`](../spec/APDU.md#clear_spent-0x31)), and `cardctl dump` skips one that fails. `SPEND_PROOF` writes only the status byte, before it signs ([D7](DECISIONS.md#d7)): a tear after the burn loses that signature, which flash-pos re-derives with `SIGN_ARBITRARY` (`resignWitness`). The order is enforced by a source scan and the torn states are tested in jCardSim; no card has been pulled mid-write. |
| 12 | Counterfeit physical cards | **Not a concern** | Value is bound to the chip's key. A look-alike with no valid chip holds nothing. |
| 13 | Supply-chain / pre-personalised cards | ⚠️ **Unaddressed** | Nothing currently attests that a card's key was generated on-card by an untampered applet. |
| 14 | Hostile reader blocks the PIN (3 unauthenticated APDUs), balance unrecoverable | ❌ **No** | `VERIFY_PIN` needs no authentication, so three wrong PINs from any reader in NFC range block the card. Once blocked, nothing can sign for its proofs: they are P2PK-locked to the card key with only a `sigflag` tag (no refund key, no locktime; [D5](DECISIONS.md#d5)'s recovery proposal is unmerged), and a reinstall regenerates the key. The balance is gone. Mitigations: small balances, a shielded sleeve, and `UNBLOCK_PIN` + PUK (ENG-617) before volume issuance. See below. |

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

## PIN-gated spending, and the blocked PIN (#2, #14)

Spending is PIN-gated once a PIN is set ([D13](DECISIONS.md#d13), which
superseded the no-PIN [D12](DECISIONS.md#d12) and resolved the decision D12
had left open under ENG-209). `SPEND_PROOF`, `SIGN_ARBITRARY`, `LOAD_PROOF`,
`CLEAR_SPENT` and `LOCK_CARD` answer `6982` until `VERIFY_PIN` succeeds in the
same NFC session.
The gate is the first statement of the spend handler, so a wrong, missing or
blocked PIN never consumes a proof. The unverified-session case is proven on
silicon (applet 0.2 on the J3R180, in the
[hardware report](HARDWARE_TEST_REPORT_2026-09-22.j3r180.md)).

The gate does not cover a card with **no PIN**. Cards ship without one, and
until one is set a reader in range can drain the card. Setting a PIN is the
holder's first job. Since applet 0.5 the holder can also take it off again:
`CLEAR_PIN` ([D15](DECISIONS.md#d15)) needs a verified session and the PIN
once more, costs a try when the PIN is wrong, and returns the card to the
no-PIN state above by the holder's choice. It is not an unblock path: a
blocked card never grants the session it needs, so #14 stands as written.

**The blocked state had its own bug (ENG-615).** Every build before applet 0.3
gated on `pinState == 1`, and a blocked card has `pinState == 2`, so three
wrong PINs *removed* the gate: the card reported itself blocked and spent
without asking (0.1 builds from before D13 gate no spend at all, and their
write gate opened the same way). A failed PIN check also left a verified
session verified, so the session that blocked the card could keep spending.
Applet 0.3 gates whenever a PIN exists in any state, and a failed check ends
the session's verification, the way `OwnerPIN.check` resets its own validated
flag. The 0.3 behaviour is verified in jCardSim only; it has not yet run on
silicon. A card whose `SELECT` answers anything below `00 03` (`00 01` or
`00 02`) runs a vulnerable build and needs the CAP reinstalled, and since
[D14](DECISIONS.md#d14) so does one answering `00 03` (#11). Sweep it first: a
reinstall regenerates the key the proofs are locked to.

**A blocked card strands its balance (#14).** `VERIFY_PIN` is unauthenticated,
so any reader in NFC range can send the three wrong PINs. Nothing but the card
key can sign for the card's proofs: the P2PK secret carries only a `sigflag`
tag, with no refund key and no locktime, and D5's recovery proposal is not
merged. ENG-615 therefore turned "three wrong PINs = theft" into "three wrong
PINs = destruction of funds". The thief gets nothing, the holder loses the
balance, and there is no unblock path in this profile.

Mitigations today: small balances and a shielded sleeve. `UNBLOCK_PIN` gated by
a provisioning PUK (ENG-617) is what removes the loss, and it blocks volume
issuance.

## What has and has not been tested

**Verified in simulation (jCardSim) and by construction:**
- BIP-340 signatures verify against an independent verifier and the spec's own vectors
- Modular arithmetic matches `BigInteger` across random and edge inputs
- Slot lifecycle, PIN gating, APDU encodings
- The blocked PIN (applet 0.3): every gated command refuses, before and after
  further PIN attempts, and a failed PIN check ends the session
- DLEQ verification, including the tagging attack it exists to catch
- NUT-11 witness checks: wrong key, wrong proof, corrupted signature, `n_sigs`

**Run on silicon** (NXP JCOP4 J3R180, 2026-09-22/23, recorded in the
[hardware report](HARDWARE_TEST_REPORT_2026-09-22.j3r180.md); applet 0.1, then
0.2 for the D13 probes):
- `cardctl selftest`: card signatures verify under BIP-340, and two signatures
  over the same message use different nonces
- Load, spend, swap and NUT-05 melt against the project mint, and a spend from
  the merchant terminal
- `SET_PIN`, `VERIFY_PIN` (wrong, then right) and `CHANGE_PIN` with the right
  current PIN
- The unverified-session gate: `LOAD_PROOF` and `CLEAR_SPENT` refuse on 0.1,
  `SPEND_PROOF` refuses on 0.2

An earlier card, a J3R452 on applet 0.1, ran the read and sign path on
2026-09-01 ([its report](HARDWARE_TEST_REPORT_2026-09-01.j3r452.md)).

**Not yet run on silicon:**
- A blocked PIN on any build: neither ENG-615 nor its 0.3 fix (the
  blocked-state gate and the failed-check session rule) has run on a card
- `LOCK_CARD`, deliberately not run on a card holding value
- EEPROM wear and lifetime
- A card pulled mid-write: the slot write order ([D14](DECISIONS.md#d14)) is
  scanned in the source and its torn states tested in jCardSim, but no card
  has been torn on purpose; power glitches short of a clean tear are
  unanalysed
- Timing/side-channel characteristics of the hand-rolled modular arithmetic
- RF range, and whether a drain attack is practical at distance

**Two bugs found in review were invisible to the simulator and would each have
been fatal in the field:** a dropped carry in the modular reduction that made
every signature invalid, and an EEPROM leak that would have bricked cards after
a few hundred taps. Treat simulator results accordingly — see
[D10](DECISIONS.md#d10).

## Open items

1. **`UNBLOCK_PIN` + PUK** (ENG-617, #14) — today three unauthenticated APDUs
   strand a card's balance for good. Blocks volume issuance
   ([D13](DECISIONS.md#d13)).
2. **Tear-off on silicon** (#11) — the write order is analysed and enforced
   ([D14](DECISIONS.md#d14)); pulling a card mid-`LOAD_PROOF` and
   mid-`CLEAR_SPENT` on hardware is still owed.
3. **Recovery** (#3) — [PR #4](https://github.com/lnflash/cashu-javacard/pull/4),
   closed unmerged, is the starting point; see [D5](DECISIONS.md#d5) for the
   flaw to fix first. A refund path would also rescue a blocked card's balance
   (#14).
4. **Card attestation** (#13) — no proof a key was generated on-card by genuine
   firmware.
5. **Side-channel review** of `SchnorrHW` — the modular arithmetic was written
   for correctness, with no constant-time analysis.
6. **Trustless proof of reserves** — upgrade the attestation to signed
   statements from the reserve wallets.

## Reporting a vulnerability

See [`SECURITY.md`](../SECURITY.md). Please do not open a public issue for
anything affecting funds.
