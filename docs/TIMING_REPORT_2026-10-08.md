# Card timing report — NXP J3R180, cashu-javacard applet 0.4

**Date:** 2026-10-08
**Author:** Flash (lnflash), in reply to a peer fork's contact-reader measurements of the same signer.
**Status:** first numbers, one card. Not a benchmark.

This document is written to be handed to a person or an agent. Every claim
points at a file, a commit, or a command in a public repository, so it can be
checked without us.

---

## 1. What was measured

One physical card, four transports, one applet build.

| Item | Value |
|---|---|
| Chip | NXP JCOP4 J3R180 P71 (SECID) |
| Applet | `cashu-javacard` 0.4 — `SELECT` returns `00 04` |
| Installed CAP | `applet/target/cashu-javacard-0.1.0.cap`, sha256 `d2947b9f907e707e…` (the tracked CAP on `main`) |
| Signer | `applet/src/main/java/me/flashapp/cashu/SchnorrHW.java`, **unchanged since `c1f4580`** (`git diff c1f4580 0274cfc -- applet/` is empty) |
| Card state | PIN set, 1556 sat loaded, 32 slots |
| Host repo state | `lnflash/cashu-javacard` `main` at `0274cfc` (PR #29 merged) |
| Terminal repo state | `lnflash/flash-pos` `main` at `d220655` (PR #77 merged) |

Transports:

| Transport | How the card was driven | Clock |
|---|---|---|
| ACS ACR122U (contactless, PC/SC) | `cardctl --timing selftest --rounds 10 --pin …` | `time.perf_counter()` around `connection.transmit()` |
| iPhone, CoreNFC | flash-pos dev build from `main`, Cashu card spend | `performance.now()` around `NfcManager.isoDepHandler.transceive()` |
| Pixel 8 Pro, Android IsoDep | same | same |
| Contact reader | peer fork's own measurement, not ours | theirs |

A figure is always the **full round trip** as the host sees it: reader or
phone NFC stack, RF link, card. It is not the applet's compute time alone.

Definitions used by the terminal log line (`[card-session] timing:`):

- **tap wait** — IsoDep request armed → tag connected. Human reach plus field
  discovery. Not separable in this instrumentation.
- **session** — tag connected → session closed. Everything the terminal did
  while the card was in the field.
- **wire** — sum of the APDU round trips inside the session.

---

## 2. Results

### 2.1 ACR122U over RF — 19 APDUs, 18/18 selftest checks passed

| Command | n | min | median | max | total |
|---|---|---|---|---|---|
| `SIGN_ARBITRARY` (BIP-340, on card) | 12 | 801.0 | **813.7** | 822.7 | 9747.8 |
| `GET_BALANCE` | 2 | 36.8 | 36.9 | 36.9 | 73.8 |
| `GET_SLOT_STATUS` | 1 | | 30.2 | | |
| `GET_PUBKEY` | 1 | | 28.0 | | |
| `VERIFY_PIN` | 1 | | 24.7 | | |
| `SELECT` | 1 | | 21.6 | | |
| `GET_INFO` | 1 | | 20.4 | | |

All figures ms. 9947 ms on the wire; the twelve signatures are 98 % of it.
`SPEND_PROOF` is a `SIGN_ARBITRARY` plus one slot status write, so the
signature row is the per-proof cost.

### 2.2 Phones — flash-pos from `main`

| Phone | Flow | `SPEND_PROOF` | Plain commands | Wire | Session | Tap wait |
|---|---|---|---|---|---|---|
| iPhone (CoreNFC) | spend, 2 proofs | **758 ms** median (755, 760) | `SELECT` 13, `VERIFY_PIN` 17, `GET_BALANCE` 24 | 1569 ms / 5 APDUs | 2280 ms | 1084 ms |
| Pixel 8 Pro | spend, 2 proofs | **1460 ms** median (1452, 1468) | `SELECT` 53, `VERIFY_PIN` 40, `GET_BALANCE` 72 | 3086 ms / 5 APDUs | 9343 ms | 529 ms |
| Pixel 8 Pro | read, all slots | — | `SELECT` 44, `GET_INFO` 25, `GET_SLOT_STATUS` 15, `GET_PUBKEY` 15, 23 × `GET_PROOF` median 19 (17–27) | 554 ms / 27 APDUs | 673 ms | 1904 ms |

Raw log lines, verbatim from the devices:

```
# Pixel 8 Pro, 15:04:20
[card-session] timing: tap wait 1904ms · session 673ms · SELECT 1× 44ms · GET_INFO 1× 25ms · GET_SLOT_STATUS 1× 15ms · GET_PROOF 23× med 19ms (17–27) · GET_PUBKEY 1× 15ms · 27 APDUs, 554ms on the wire
# Pixel 8 Pro, 15:04:35
[card-session] timing: tap wait 529ms · session 9343ms · SELECT 1× 53ms · VERIFY_PIN 1× 40ms · SPEND_PROOF 2× med 1460ms (1452–1468) · GET_BALANCE 1× 72ms · 5 APDUs, 3086ms on the wire
# iPhone, 15:06:55
[card-session] timing: tap wait 1084ms · session 2280ms · SELECT 1× 13ms · VERIFY_PIN 1× 17ms · SPEND_PROOF 2× med 758ms (755–760) · GET_BALANCE 1× 24ms · 5 APDUs, 1569ms on the wire
```

### 2.3 One signature, four transports, one card

| Transport | Per signature | Per plain command |
|---|---|---|
| Contact reader (peer fork, their card) | ≈ 740 ms | ≈ 60 ms |
| iPhone, CoreNFC | 758 ms | 13–24 ms |
| ACR122U over RF | 814 ms | 20–37 ms |
| Pixel 8 Pro | 1460 ms | 40–72 ms |

---

## 3. Reading the numbers

**The signature is the whole story, and it is the same on both cards.** Our
814 ms over the ACR122U and 758 ms on the iPhone bracket the peer's 740 ms on
contact. The signer is byte-identical across the two forks, so this is one
number measured four ways.

**It is field-power bound.** The spread across transports (740 → 758 → 814 →
1460) tracks how much power the card gets, not the host stack: the iPhone
and a contact reader agree, and the Pixel, whose field is the weakest here,
runs the same loop at nearly half speed. The same effect is why Android's
default 618 ms IsoDep transceive budget had to be raised in flash-pos
(`src/services/cashuCardNfc.ts`, `CARD_TRANSCEIVE_TIMEOUT_MS`). Any
arithmetic win in the signer pays off almost double on that phone.

**It is a fixed-cost loop, not data-dependent.** Twelve signatures over
random messages on the ACR122U span 22 ms, 2.7 % of the median. The two
phone pairs span 5 and 16 ms.

**Where the ~800 ms goes.** `SchnorrHW.sign()` (line 311 on) does, per signature:

| Step | Implementation | Cost class |
|---|---|---|
| aux randomness | `RandomData.ALG_SECURE_RANDOM` | native, small |
| three tagged SHA-256 (aux, nonce, challenge) | `MessageDigest.ALG_SHA_256` | native, small |
| **R = k·G** | `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` (line ~414) | **coprocessor** |
| k mod n, e mod n | `reduceModN` — compare and one conditional subtract | interpreted, cheap |
| n − k, n − d (even-y normalisation) | `subtractFromN` | interpreted, cheap |
| **e·d mod n** | `mulModN` (line 531): schoolbook 256×256 → 512 (`mul256x256`, 545), then `reduce512toModN` (584) applying 2²⁵⁶ ≡ Δ (mod n) twice via `mulSmallByDelta` (651) | **interpreted, ≈ 3000 byte-multiplies in JCVM bytecode** |
| s = k + e·d | `addModN` | interpreted, cheap |

So the point multiply is already off the interpreter. The ~800 ms is almost
entirely one modular multiplication done in Java Card bytecode. This is
consistent with the peer's own reading ("interpreted big-number arithmetic").

**Plain commands are reader-stack, not card.** 13–24 ms on CoreNFC, 20–37 ms
on the ACR122U, 40–72 ms on the Pixel, ≈ 60 ms on the peer's contact reader.
Nothing in the applet differs between these; the host side does.

---

## 4. Answers to the three questions asked

1. **Per-SPEND on the J3R180 over NFC from a phone:** iPhone **758 ms**,
   Pixel 8 Pro **1460 ms** (n = 2 each, section 2.2).
2. **Per-command latency over CoreNFC, and baud rate:** 13–24 ms for the
   short commands here, the lowest of any transport we have. Whether iOS
   negotiates above 106 kbit/s is **not visible** in these numbers: the
   commands are too short for link rate to show beside per-command overhead.
   A deliberate test would send a maximal-length response (e.g. a 255-byte
   `GET_PROOF` page) and compare against 106 kbit/s arithmetic.
3. **A cheaper Schnorr on JCOP4:** not found yet. k·G is already native.
   Two things we have not tried, section 5.

---

## 5. Ways down, untried, in order of expected payoff

### 5.1 Protocol: NUT-11 `sigflag: SIG_ALL` — one signature per payment

With `SIG_ALL`, the P2PK witness is one signature over the concatenation of
all input secrets and all output blinded messages, carried on the first
proof's witness. Nine proofs become nine slot burns and **one** signature:
≈ 7.5 s of signing becomes ≈ 0.8 s on the iPhone, ≈ 13 s becomes ≈ 1.5 s on
the Pixel. This dominates any arithmetic change for multi-proof payments.

Requirements: the mint must accept `SIG_ALL` (Nutshell does), the terminal
must build the message, and the applet must mark every slot spent **before**
the single sign, keeping the spend-before-sign ordering the current
`SPEND_PROOF` enforces (`docs/DECISIONS.md`, D14 and the tear-off work in
PR #26). Card-side this is a new instruction, not a change to `SchnorrHW`.

### 5.2 Arithmetic: modular multiply on the RSA coprocessor

The JCMathLib technique: a `Cipher.ALG_RSA_NOPAD` with public exponent 2 and
modulus n computes x² mod n on the coprocessor. Then
2ab = (a + b)² − a² − b², and halving mod odd n is a shift (add n first if
odd). Three RSA operations and a few 256-bit adds replace the schoolbook
loop in `mulModN`.

Caveats to check first on this card: JCOP generally requires RSA moduli of
512 bits or more, and may reject a modulus with leading zero bytes. JCMathLib
has working arrangements for this; read its `Bignat.mod_mult` before
designing a new one. Expected win if it works: the ~800 ms drops toward the
native EC + hash floor, which section 3 suggests is well under 100 ms.

### 5.3 Smaller: fewer reads

Our full-card read is 27 APDUs (one `GET_PROOF` per slot). The peer reads
"pieces three to a page". At 19 ms per `GET_PROOF` on the Pixel this is a
few hundred ms, so it is third on the list, but a paged read is cheap to add.

---

## 6. A terminal finding, not a card finding

The Pixel spend session held the card for **9.3 s** against **3.1 s** of
APDU time. The iPhone held it for 2.3 s against 1.6 s. Six seconds of the
Android spend are terminal-side work inside the session (persisting the
settlement queue entry, building the witness, or something else; not yet
identified). It is independent of the card and is the next item in
flash-pos.

---

## 7. Caveats

- One card. One build. Phone signature figures are n = 2; the reader figure
  is n = 12.
- The contact-reader column is the peer's measurement of **their** card, not
  ours. Same signer source, different silicon.
- `tap wait` includes the human. Do not compare it across runs.
- The PIN was set on this card, so every signing session paid one
  `VERIFY_PIN` (17–40 ms) that a PIN-less card would not.
- Phone timing wraps `transceive()` in JavaScript; the iOS and Android
  bridges add overhead that the PC/SC figure does not have. The small plain-
  command figures bound that overhead at a few ms on iPhone.

---

## 8. How to reproduce

Reader (needs `pyscard` in a venv; system Python on macOS lacks it):

```bash
git clone https://github.com/lnflash/cashu-javacard && cd cashu-javacard/tools/cardctl
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python cardctl.py --timing selftest --rounds 10 [--pin NNNN]
.venv/bin/python cardctl.py -t spend 0            # one SPEND_PROOF, timed — burns the slot
```

Phone (flash-pos dev build from `main` at `d220655` or later):

1. Tap the card on **Profile → Settings → Cashu card (dev)** for a read, or
   charge and tap for a spend.
2. Read the line `[card-session] timing:` from Metro, or directly from the
   device:
   - Android: `adb logcat -v time -s 'ReactNativeJS:*' | grep 'card-session] timing'`
   - iOS (libimobiledevice): `idevicesyslog -u <udid> | grep 'card-session] timing'`

---

## 9. References

All in public repositories. Paths are relative to each repo's root; commits
are the state this report was taken at.

**`lnflash/cashu-javacard` @ `0274cfc`** (this report lives at
`docs/TIMING_REPORT_2026-10-08.md`; the dated section in
`docs/HARDWARE_TEST_REPORT_2026-09-22.j3r180.md` has the same numbers in
context of the earlier silicon runs)

| What | Where |
|---|---|
| The signer | `applet/src/main/java/me/flashapp/cashu/SchnorrHW.java` — `sign()` 311, `mulModN` 531, `mul256x256` 545, `reduce512toModN` 584, `mulSmallByDelta` 651; header comment describes the algorithm and the memory discipline |
| Applet dispatch, `SPEND_PROOF` spend-before-sign ordering | `applet/src/main/java/me/flashapp/cashu/CashuApplet.java` |
| Timing instrumentation | `tools/cardctl/cardctl.py` — `record_timing`, `summarize_timings`, `Card.transmit`; `--timing` flag in `build_parser`; tests at the end of `tools/cardctl/test_apdu.py` |
| Wire format | `spec/APDU.md` (every INS, P1/P2, Le, status words) |
| Card-side protocol | `spec/NUT-XX.md` (Profile B, proof reconstruction from nonce + pubkey) |
| Design decisions incl. tear-off ordering | `docs/DECISIONS.md` |
| PR that added `--timing` | https://github.com/lnflash/cashu-javacard/pull/29 |
| PR carrying the numbers into the hardware report | https://github.com/lnflash/cashu-javacard/pull/30 |

**`lnflash/flash-pos` @ `d220655`**

| What | Where |
|---|---|
| Collector | `src/services/apduTiming.ts` — `recordApdu`, `summarizeApduTimings` (median, not mean) |
| Where each APDU is timed | `src/services/cashuCard.ts` — `timedTransceive`, used by `send()` and `selectApplet()`; bucketed by INS name |
| Session line, tap wait / session definitions | `src/services/cashuCardNfc.ts` — `withCardSession` |
| Android transceive budget and why | `src/services/cashuCardNfc.ts` — `CARD_TRANSCEIVE_TIMEOUT_MS` comment |
| PR | https://github.com/lnflash/flash-pos/pull/77 |

**External**

| What | Where |
|---|---|
| BIP-340 | https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki |
| NUT-11 (P2PK, `SIG_ALL`) | https://github.com/cashubtc/nuts/blob/main/11.md |
| JCMathLib (RSA-coprocessor modular multiply on Java Card) | https://github.com/OpenCryptoProject/JCMathLib |
