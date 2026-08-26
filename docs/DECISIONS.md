# Design decisions

Each entry records a call that was made, what was rejected, and why. If you are
about to change one of these, read the entry first — most were made against a
real alternative, and several were made *after* getting it wrong once.

Anchors are stable (`#d1` … `#d12`); other docs link to them.

---

## <a id="d1"></a>D1 — Cashu ecash, not BoltCard

**Rejected:** NTAG 424 DNA + AES-128 CMAC, per **FIP-04 (Implemented)**.

A BoltCard authenticates *who is tapping* against a server-side balance. It
cannot work offline, because the terminal must reach the server to learn whether
the balance exists.

Cashu proofs are bearer tokens: valid because they carry the mint's blind
signature, verifiable by arithmetic rather than by asking a server. That is what
buys offline payment, and offline payment is the requirement that started the
project ([`VISION.md`](VISION.md)).

**Cost accepted:** a far more demanding chip (secp256k1 rather than AES), higher
unit cost (~$5 vs ~$1), and the offline double-spend exposure in
[`SECURITY-MODEL.md`](SECURITY-MODEL.md). `btcpayserver-flash-plugin` is being
decommissioned as a result (ENG-176).

---

## <a id="d2"></a>D2 — No cardholder identity, ever

**Rejected:** name, card number, PIN-on-spend by default, remote freeze, recovery.

The card is cash. Each of those features is individually reasonable and
collectively turns the product into a debit card with extra steps — at which
point Flash is custodial again and the reason to exist is gone.

This is why the physical card says **"BEARER CARD"** rather than leaving the
name field blank: it is a statement, not an omission
([`flash-card-assets`](https://github.com/lnflash/flash-card-assets)).

**Consequence to accept:** lost card = lost funds, and the card says so in plain
language on the back. That copy is deliberate and is not to be softened without
sign-off.

---

## <a id="d3"></a>D3 — The card does no BDHKE

**Rejected:** blinding/unblinding on-card.

JavaCard has no big integers, no `long`, and no garbage collector. Implementing
blinding on-card would multiply applet size and attack surface to protect
something that is not secret — and the host must know the blinding factor `r`
anyway in order to unblind.

The card holds the one thing that genuinely cannot live elsewhere: a private key
that has never existed outside the secure element. Everything else belongs on
the host.

---

## <a id="d4"></a>D4 — Proofs are P2PK-locked to the card key (NUT-11)

Without this, reading a card's memory would be equivalent to stealing its
balance — the proofs would be spendable by whoever copied them.

With [NUT-11](https://github.com/cashubtc/nuts/blob/main/11.md), a proof is
locked to a public key whose private half exists only inside the chip. A
passive dump yields proofs that cannot be redeemed.

**This is the decision that makes a bearer *card* possible** rather than merely
a bearer token. It is also why the provisioning host must know the card's public
key *before* minting: the lock is applied at issuance, not afterwards.

---

## <a id="d5"></a>D5 — No seed, no backup, no recovery

**Rejected:** BIP-39 seed derivation for the card key.

A recoverable card is a card whose funds exist somewhere other than the card,
which contradicts D2. It also means the recovery secret becomes the real
credential and the chip stops being the security boundary.

**This is the most-questioned decision, and the open counter-proposal is good.**
[PR #4](https://github.com/lnflash/cashu-javacard/pull/4) proposes using NUT-11's
existing `refund` + `locktime` tags so a lost card's proofs can be swept to a
recovery key after a timeout — no applet key changes, no seed. It is the right
shape. It is not merged because of a specific flaw: in NUT-11, once locktime
passes the *card's own key stops being valid*, so a short locktime silently
converts the card into a brick; and the card cannot enforce a timeout because
JavaCard has no clock, so a merchant would accept a tap that the mint later
refuses.

If you want to solve recovery, start from that PR and that objection.

---

## <a id="d6"></a>D6 — JavaCard 3.0.5 is a hard floor

The Schnorr signer computes `k·G` using
`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`. That constant **was introduced in
JavaCard 3.0.5 and does not exist in 3.0.4** — verified by inspecting the SDK
jars directly, not by reading a datasheet.

This invalidated the project's own prior documentation, which named Feitian
3.0.4 as the primary target and JCOP4 as a fallback. Every external
documentation contribution repeated that error, because the README told them to.

**Practical effect:** JCOP3, J3H145 and Feitian 3.0.4 parts cannot run this
applet at all. Confirm the platform version in writing before buying a tray.

---

## <a id="d7"></a>D7 — The client refuses locally rather than letting the mint refuse

`meltProofs` and `swapProofs` validate a proof's NUT-11 witness **before**
submitting, and return an error rather than forwarding a request the mint would
reject.

This looks like belt-and-braces. It is not. The ordering is asymmetric:

```
SPEND_PROOF  → card marks the slot SPENT, returns the signature   ← irreversible
meltProofs   → mint accepts or rejects                            ← too late
```

By the time a terminal is assembling a melt, **the card has already burned its
slot**. A mint-side rejection is not free — it costs the proof. Failing locally
leaves it intact.

The same reasoning drives `selectProofsForMelt` returning `null` rather than a
short selection, and the local witness check honouring `sigflag` and `n_sigs`:
**a check looser than the mint's passes locally and still burns the slot.**

---

## <a id="d8"></a>D8 — Melt and swap are not idempotent, and the API says so

There is no request-id or retry token. Inputs are consumed the moment the mint
accepts them, so a lost response is genuinely ambiguous.

The library does not paper over this. It documents that after a lost response
the correct move is `getMeltQuoteState` or `checkProofStates` — **never a
retry** — because a retry against a `PENDING` quote is how the same invoice gets
paid twice.

Related: `allProofsUnspent` returns `"UNSPENT" | "NOT_UNSPENT" | CashuMintError`
rather than a boolean. A boolean union fails open — `CashuMintError` is a truthy
object, so `if (await allProofsUnspent(...))` would read a mint timeout as
"safe to accept", inverting the double-spend check. This was a real bug, caught
in review.

---

## <a id="d9"></a>D9 — BIP-340 *default* signing, with auxiliary randomness

**Rejected:** a deterministic nonce derived purely from `(d, msg)`.

Deterministic nonces are attractive because they are testable against fixed
vectors. On a bearer card they are dangerous: a nonce that is a pure function of
key and message hands a fault-injection attacker two signatures over the same
`k`, and `d = (s₁−s₂)/(e₁−e₂)` falls straight out.

The signer therefore folds fresh aux randomness into the nonce, exactly as
BIP-340 specifies for default signing. **Signatures over the same message are
deliberately not reproducible**, which is why `cardctl selftest` checks that two
signatures over one message differ, and why the BIP-340 signing vectors cannot
be replayed against the card.

---

## <a id="d10"></a>D10 — Every buffer is allocated once, at install time

JavaCard Classic allocates `new` in **persistent EEPROM** and never collects it.
An allocation on the signing path is a permanent leak.

The original signer allocated 288 bytes per `sign()` call. A card would have run
out of persistent memory after a few hundred taps and been **permanently dead
for spending** — recoverable only by deleting the applet instance, which
destroys the stored proofs.

jCardSim cannot surface this: it runs on the JVM, with a heap and a garbage
collector. The suite was green. **A source-level scan now enforces the rule**,
because the runtime cannot.

The general lesson, which applies to every change in `applet/`: *a passing
simulator suite is not evidence about silicon.*

---

## <a id="d11"></a>D11 — DLEQ is verified client-side, and unlinkability is not assumed

A mint could sign one user's outputs with a key unique to them and recognise
those proofs on redemption, breaking the unlinkability that is the point of
ecash. [NUT-12](https://github.com/cashubtc/nuts/blob/main/12.md) DLEQ proves
the signature used the *published* key.

It is verified in `cashu-client`, in local arithmetic, with no mint contact —
which is what lets an **offline terminal** check a tap on arithmetic rather than
on faith.

The mint is trusted for solvency. It is explicitly *not* trusted for
unlinkability.

---

## <a id="d12"></a>D12 — No PIN on spending, in the base profile

`SPEND_PROOF` requires no authentication. `LOAD_PROOF`, `CLEAR_SPENT` and
`LOCK_CARD` are PIN-gated; spending is not.

That is bearer semantics: possession authorises payment, as with a banknote. It
is also the design's sharpest edge — **a hostile reader in range can drain a
card**, and the spec's Profile B+ (PIN-gated spending) is written but not
implemented.

This is a genuine open product decision, not a settled one. It is tracked
against the same fraud finding that covers the current Flashcard's re-link gap
(ENG-209), and it should be resolved before any volume issuance. See
[`SECURITY-MODEL.md`](SECURITY-MODEL.md).

---

## How to propose a change to one of these

Small changes: open a PR and reference the decision id (e.g. "revisits D5").

Changes that alter the product's shape — recovery, identity, custody, the
trust boundaries in [`ARCHITECTURE.md`](ARCHITECTURE.md) — warrant a **Flash
Improvement Proposal**. That process exists precisely for "large-scale or
cross-team changes", and this project does not yet have one of its own: the
closest is FIP-04, which describes the design being replaced. *(The FIP
repository is internal to Flash.)*
