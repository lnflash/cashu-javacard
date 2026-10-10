# Design decisions

Each entry records a call that was made, what was rejected, and why. If you are
about to change one of these, read the entry first — most were made against a
real alternative, and several were made *after* getting it wrong once.

Anchors are stable (`#d1` … `#d15`); other docs link to them.

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

**This is the most-questioned decision, and the counter-proposal is good.**
[PR #4](https://github.com/lnflash/cashu-javacard/pull/4) proposed using NUT-11's
existing `refund` + `locktime` tags so a lost card's proofs can be swept to a
recovery key after a timeout — no applet key changes, no seed. It is the right
shape. It was closed unmerged on 2026-10-02, because it was written before
v0.2.0 and no longer applies, and because of a specific flaw: in NUT-11, once
locktime passes the *card's own key stops being valid*, so a short locktime
silently converts the card into a brick; and the card cannot enforce a timeout
because JavaCard has no clock, so a merchant would accept a tap that the mint
later refuses.

Since 0.3, a card whose PIN is blocked strands its balance too
([SECURITY-MODEL](SECURITY-MODEL.md) #14), so a refund path would rescue a
blocked card as well as a lost one.

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

## <a id="d12"></a>D12 — No PIN on spending, in the base profile (SUPERSEDED by D13)

`SPEND_PROOF` requires no authentication. `LOAD_PROOF`, `CLEAR_SPENT` and
`LOCK_CARD` are PIN-gated; spending is not.

That is bearer semantics: possession authorises payment, as with a banknote. It
is also the design's sharpest edge — **a hostile reader in range can drain a
card**, and the spec's Profile B+ (PIN-gated spending) is written but not
implemented.

This was a genuine open product decision, tracked against the same fraud
finding that covers the current Flashcard's re-link gap (ENG-209).
**Resolved by [`D13`](#d13): spending is PIN-gated when a PIN is set.**

---

## <a id="d13"></a>D13 — PIN-gated spending on personalised cards (supersedes D12)

`SPEND_PROOF` and `SIGN_ARBITRARY` are PIN-gated **when a PIN is set**;
`VERIFY_PIN` in the same NFC session authorises both. `LOAD_PROOF`,
`CLEAR_SPENT` and `LOCK_CARD` keep their existing gate. Cards provisioned
without a PIN keep the D12 tap-and-go behaviour.

This resolves the open decision D12 deferred (Profile B+; ENG-209): the pilot
chose Visa-style authorisation — possession **and** knowledge authorise
payment — because a hostile reader in the D12 model could drain a card it was
presented, and because POS cards now ship PIN-set by default.

Why `SIGN_ARBITRARY` is gated with it: the signature is a spend authorisation
under the card's key (it is the recovery path's witness material), so an
unverified session must not be able to mint one — otherwise the spend gate is
theatre.

Burn ordering is unaffected: the gate is the first statement of the spend
handler, so a wrong or missing PIN throws `6982` **before** the slot burn —
no proof is consumed on a failed authorisation.

**Lockout semantics (pilot):** `PIN_MAX_TRIES` (3) exhausted → `6983`, the
card's PIN-verified operations are dead, and there is **no unblock path** in
this profile — a blocked card is replaced at re-provisioning. An
`UNBLOCK_PIN` command gated by a provisioning PUK is the designated follow-up
**before volume issuance**; do not ship consumer cards at scale without it.

*Correction (ENG-615, after v0.2.0):* "dead" was not what the applet did. The
gate checked `pinState == 1`, and a blocked card has `pinState == 2`, so
exhausting the tries **removed** the gate: every PIN-gated command opened up
to whoever held the card, while `VERIFY_PIN` and `GET_INFO` kept reporting it
blocked. `CHANGE_PIN` had the mirror bug — its failed checks decremented the
counter without ever setting `pinState`, leaving a card that reported "set"
but could never verify. And no failed check ended the session, so a session
that had verified stayed verified through later wrong PINs, including the
ones that blocked the card. All three are fixed in applet 0.3: the gate fires
whenever a PIN exists in any state; one helper owns the blocked transition for
every PIN check; and a failed check ends the session's verification, as
`OwnerPIN.check` does for its own validated flag. That last rule also means
`CHANGE_PIN` can no longer exhaust the counter: it needs a verified session,
and the `VERIFY_PIN` that opens one resets the counter.

The fix changes wire behaviour, so the applet version moved to 0.3. Every 0.1
and 0.2 build has the same `pinState == 1` gate on `LOAD_PROOF`, `CLEAR_SPENT`
and `LOCK_CARD`, and 0.1 builds from before D13 gate no spend at all, so a card
whose `SELECT` answers anything below `00 03` (`00 01` or `00 02`) needs the
CAP reinstalled. There is no proof-preserving upgrade, so sweep first: the
reinstall regenerates the card key. [D14](#d14) later moved that floor to
`00 04`.

"Dead" also means **stranded**. Nothing but the card key can sign for the
card's P2PK-locked proofs, so a blocked card's balance is unrecoverable, and
`VERIFY_PIN` is unauthenticated: any reader in range can block a card with
three APDUs ([`SECURITY-MODEL.md`](SECURITY-MODEL.md) #14). That loss is what
`UNBLOCK_PIN` + PUK (ENG-617) has to remove.

Provisioning: POS cards are personalised with a PIN by default
(`cardctl set-pin` during personalisation; `fund-card --pin` when the funding
tool gains it). The merchant terminal prompts for the PIN only when
`GET_INFO.pinState` reports `set`, and refuses a card reporting `locked` (2)
outright: nothing can spend from it. Since applet 0.5 a holder can take the
PIN off again ([D15](#d15)), so the terminal reads `pinState` on every tap.

---

## <a id="d14"></a>D14 — A slot's status byte is its commit, written last

A proof slot is `status ‖ keyset ‖ amount ‖ nonce ‖ C`, and every reader trusts
the status byte: `GET_BALANCE` sums the UNSPENT slots and `SPEND_PROOF` signs
for them. So every write to a slot changes its data first and its status byte
last, as a single byte, which the JCRE writes atomically. A card that leaves
the field mid-write leaves the slot with its old status, never a new status
over old bytes:

- `LOAD_PROOF` copies the proof (`Util.arrayCopy`, atomic into persistent
  memory), then sets UNSPENT. Torn before the commit, the slot is still EMPTY:
  no command reads it, and the next `LOAD_PROOF` overwrites it.
- `CLEAR_SPENT` zeroes a spent slot's data, then sets EMPTY. Torn mid-fill (the
  fill is not atomic), the slot is still SPENT: never counted or signed for, and
  the next `CLEAR_SPENT` finishes it. Until then `GET_PROOF` still returns it,
  with some fields zeroed, and its data is not a proof: see
  [`spec/APDU.md`](../spec/APDU.md#clear_spent-0x31) for what a reader
  checks. An EMPTY slot never holds a spent proof's bytes.
- `SPEND_PROOF` writes only the status byte ([D7](#d7)).

**Rejected:** a `JCSystem` transaction around each write. The order alone gives
the guarantee, and a transaction around the old handlers would not have given
it: the old `CLEAR_SPENT` filled the whole slot, status byte included, with
`Util.arrayFillNonAtomic`, which does not use the transaction facility even
while a transaction is in progress. Torn inside a transaction as outside one,
that fill could leave an EMPTY status over a spent proof's bytes, the state
ENG-620's resurrection starts from. A transactional clear needs `Util.arrayFill`
(JC 3.0.5) in its place. Nor does the order keep `LOAD_PROOF` off the commit
buffer: its `Util.arrayCopy` is atomic into persistent memory and subject to the
same commit capacity a transaction uses (it can throw `TransactionException`).
The order does not rely on that atomicity, since a torn copy leaves the slot
EMPTY whatever its bytes hold, so `Util.arrayCopyNonAtomic` would be as safe
there.

*Found after v0.2.0 (ENG-620):* `LOAD_PROOF` set UNSPENT before it copied the
proof, and `CLEAR_SPENT` zero-filled from the status byte. A tear between
`LOAD_PROOF`'s two writes left an UNSPENT slot over the slot's old bytes:
usually zeros, a phantom proof of amount 0 that `CLEAR_SPENT` would not free
(it frees only SPENT slots) until a `SPEND_PROOF` burned it; after a torn
`CLEAR_SPENT` of the same slot, a spent proof's keyset, amount and C, which
`GET_BALANCE` counted and an offline terminal could accept and never settle.

jCardSim cannot tear a write, so `SlotWriteOrderTest` scans the source for the
order, as D10's allocation rule is scanned, and sets the torn states directly to
show what every command then does.

Outside a torn write nothing a reader sends or receives changes, but the applet
version moved to 0.4 anyway. No release carries the one 0.3 build with the old
order (`958a8baa…`), but it was `main`'s tracked CAP from `f889934` until this
fix, and whether a card was installed from it in that window could not be
confirmed. `SELECT`'s version is the only thing an installed card reports about
its build, so the 0.3 builds cannot be told apart: a card answering `00 03` may
run the old order. Keeping 0.3 and telling builds apart by the tracked CAP's
sha256 was rejected for that reason: the hash says which CAP to install, not
which one a card already runs. A card whose `SELECT` answers anything below
`00 04` needs the CAP reinstalled (sweep it first), and `cardctl selftest`
fails it ([`HARDWARE_DEPLOYMENT.md`](HARDWARE_DEPLOYMENT.md#install)).

---

## <a id="d15"></a>D15 — A holder can take the PIN off a personalised card (qualifies D13)

`CLEAR_PIN` (`0x43`, applet 0.5) removes the PIN from a card that has one.
The card goes back to where `SET_PIN` found it: `pinState` 0, a fresh try
counter, every gated command open with no PIN, `VERIFY_PIN` answering `6984`,
and `SET_PIN` allowed again. D13 stays the default — POS cards still ship
PIN-set, and nothing but this command, sent by someone who has verified the
PIN in the same session and presents it again, takes a PIN off. This adds an
explicit, PIN-authenticated way out; it does not reopen D12.

Why a holder wants it: the card is cash ([D2](#d2)), and the PIN is the
holder's choice of how much that cash should behave like a banknote. A card
handed to someone else, a small-balance card for a tap-and-go merchant, a
card whose holder decides the D13 prompt costs more than the D12 exposure
it closes — each is the holder's call, on their own money, and before 0.5
the only route was a reinstall, which regenerates the card key and strands
the balance ([D5](#d5)). An owner who can set a PIN and cannot remove it is
holding a card with a feature they cannot turn off.

**Rejected:**

- *`SET_PIN` re-callable, or `CHANGE_PIN` with an empty new PIN.* Both
  overload a command that means something else; a reader that sends one
  expects a PIN to exist afterwards. Clearing is its own instruction, with
  its own capability bit (byte 6 bit 3), so a reader can tell from `GET_INFO`
  whether the card answers it or `6D00`.
- *Clearing on the verified session alone, without the PIN in the data
  field.* The session flag is the card's own, but the command that removes
  the one gate on the money asks for the PIN again, as `CHANGE_PIN` does
  before it replaces it. A wrong PIN here costs a try through the same
  helper (`failPinCheck`), so `CLEAR_PIN` is no cheaper to guess against than
  `VERIFY_PIN`, and like `CHANGE_PIN` it cannot be the try that blocks the
  card: the failure ends the session, and the `VERIFY_PIN` that reopens one
  resets the counter.
- *Clearing a blocked PIN.* This is the ENG-615 lesson, and the line this
  command must not cross. State 2 is reached by three unauthenticated APDUs
  from any reader in range; a `CLEAR_PIN` that took a blocked card to state
  0 would be the unblock path D13 says does not exist, handed to whoever
  blocked it — three wrong PINs, then a clear, then a spend. The gate is
  `requirePinVerified`, which a blocked card can never pass, so state 2
  answers `6982` with the right PIN, in this session and the next. The test
  for it sends exactly that sequence. The stranded-balance problem ([D13](#d13),
  [SECURITY-MODEL #14](SECURITY-MODEL.md)) is still `UNBLOCK_PIN` + PUK's
  (ENG-617) to solve, not this command's.

The write is one byte: `pinState` to 0, after the check — the byte `SET_PIN`
writes last, the other way. The JCRE writes a byte atomically, so a card pulled
mid-command is PIN-set or it is not; there is no state between. The try
counter needs no write of its own: `OwnerPIN.check`'s contract is that a
match sets the validated flag and resets the tries remaining, so the
successful check `CLEAR_PIN` runs just before the write has already left
the counter at its limit, and the card leaves as `SET_PIN` found it with
`pinState` the only persistent byte the command touches.

*Corrected before merge:* the first draft followed the byte with
`OwnerPIN.resetAndUnblock()` inside a `JCSystem` transaction and described
the order of the two as load-bearing, as [D14](#d14)'s is. It was not. The
reset re-filled a counter the check had already filled, so neither tear it
guarded against — state 0 over a stale counter, state 1 over a fresh one —
could happen; the "fresh counter" is one the holder had already earned by
verifying. A write order documented as a guarantee when it is not is worse
than none, since the next change protects the wrong thing, so both calls
went and `ClearPinTest` now scans for the opposite: the check precedes the
write, and the state byte is the only persistent write. The test still sets
`pinState` 0 over a partly spent counter and shows nothing reads it
(`VERIFY_PIN` stops at `6984`; the next `SET_PIN`'s `OwnerPIN.update`
starts its PIN at the full count), as a property of state 0 the applet must
keep, not a state `CLEAR_PIN` can leave.

Readers: `pinState` 1 is no longer a one-way state, so a terminal reads
`GET_INFO` byte 7 on every tap rather than remembering a card as PIN-set.
`cardctl clear-pin --pin` drives it (`VERIFY_PIN`, then `CLEAR_PIN`); `info`
names the capability. flash-mobile's card screen is the follow-up: a
"Remove PIN" action behind the PIN prompt, offered only when byte 6 bit 3 is
set.

The applet version moved to 0.5: a new instruction and a new capability bit
are wire-visible, and a 0.4 card answers `0x43` with `6D00`. A 0.4 card is
not vulnerable and need not be reinstalled; it lacks the feature. 0.5 is a
fresh install (delete + install, sweep first), as every applet version is —
there is no in-place upgrade.

---


Small changes: open a PR and reference the decision id (e.g. "revisits D5").

Changes that alter the product's shape — recovery, identity, custody, the
trust boundaries in [`ARCHITECTURE.md`](ARCHITECTURE.md) — warrant a **Flash
Improvement Proposal**. That process exists precisely for "large-scale or
cross-team changes", and this project does not yet have one of its own: the
closest is FIP-04, which describes the design being replaced. *(The FIP
repository is internal to Flash.)*
