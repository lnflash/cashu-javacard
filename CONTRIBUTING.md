# Contributing to cashu-javacard

An open-source implementation of [NUT-XX: Cashu NFC Card Protocol](spec/NUT-XX.md).
Contributions are welcome — including from people who have never touched a
smartcard before.

**Read [`docs/DECISIONS.md`](docs/DECISIONS.md) before proposing a change to how
the product behaves.** Most of what looks like a missing feature — recovery, a
cardholder name, a PIN on spending — is a decision with reasoning behind it, and
several were made after getting it wrong once. Arguing against a decision is
welcome; not knowing it exists wastes your time.

## Pick your path

### Casual contributor / first time here

Start with [`docs/VISION.md`](docs/VISION.md) and
[`docs/GLOSSARY.md`](docs/GLOSSARY.md). You do not need a card, a reader, or any
JavaCard knowledge to help.

Genuinely useful without hardware:
- **Documentation that is true.** See the warning below first.
- **`cardctl`** (`tools/cardctl/`) is plain Python with tests that run anywhere.
- **`cashu-client`** ([separate repo](https://github.com/lnflash/cashu-client))
  is TypeScript, and the mint protocol is well specified by the NUTs.
- **Reading the spec against the code** and reporting where they disagree. This
  has already caught real bugs.

> ⚠️ **On documentation PRs specifically.** This repo previously carried an open
> issue asking for user-facing docs, and received ten separate submissions that
> went unanswered for months. That was our failure and the issue is now closed.
>
> If you write docs here, the bar is **verifiable accuracy**. Every one of those
> ten submissions confidently described a merchant tap-to-pay flow that does not
> exist, and repeated a hardware compatibility claim that was wrong — because
> our own README told them so. Some invented terminal output and quoted
> performance figures for code that had never run.
>
> Write what you can check. Mark the rest as unverified. That is more valuable
> than polish.

### Developer

```
docs/VISION.md → docs/ARCHITECTURE.md → docs/DECISIONS.md → here
```

Then pick a layer:

| Layer | Language | Hardware needed |
|---|---|---|
| Applet (`applet/`) | JavaCard | No — jCardSim |
| Host driver (`tools/cardctl/`) | Python | Only for `selftest` |
| Mint protocol ([cashu-client](https://github.com/lnflash/cashu-client)) | TypeScript | No |
| **Merchant terminal** | — | **Nobody is building this. It is the biggest gap.** |

### AI agent

Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md),
[`docs/DECISIONS.md`](docs/DECISIONS.md) and
[`docs/GLOSSARY.md`](docs/GLOSSARY.md) before editing. Three rules that matter
more here than in an ordinary repo:

1. **JavaCard is not Java.** No `long`, no `BigInteger`, no `String` at runtime,
   no collections, no garbage collector. Code that compiles under `javac` can
   still be rejected by the CAP converter — or, worse, convert cleanly and leak
   EEPROM on every tap.
2. **A green test suite is not evidence about silicon.** jCardSim runs on the
   JVM. It cannot reproduce EEPROM exhaustion, ECDH output framing, or a card
   whose `getS` returns short — all real bugs found here.
3. **Do not assert what you did not verify.** If you did not run it, say so.

## Development setup

### Prerequisites

- JDK 11+
- Maven 3.8+ (tests) and Apache Ant 1.10+ (CAP build)
- JavaCard SDK 3.0.5+ — `git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/.javacard/sdks`
  (3.0.4 is **not** sufficient: `ALG_EC_SVDP_DH_PLAIN_XY` is 3.0.5+)
- jCardSim (pulled in by Maven; no hardware required for tests)
- Python 3.11+ for `tools/cardctl` — **not** macOS system Python 3.9, whose
  `pyscard` build fails at import

### Running tests

```bash
mvn -f applet/pom.xml test                    # applet
cd tools/cardctl && python3 test_bip340.py && python3 test_apdu.py
```

No hardware required for either.

### Building the CAP

```bash
ant -f applet/build.xml cap
```

CI runs the applet suite on JDK 11 and 17, the `cardctl` suite on Python 3.11
and 3.13, and the CAP conversion, on every push.

## Key design principles

1. **Security first.** The card's private key must never leave the chip.
2. **Spend protection is irreversible.** A slot marked spent must never be
   unmarked. No APDU may exist that does so.
3. **Spec alignment.** Commands must match NUT-XX. If the spec is ambiguous,
   raise it before implementing.
4. **Portability.** Any JavaCard 3.0.5+ chip with secp256k1. Avoid
   chip-specific APIs.
5. **No allocation after install.** JavaCard Classic allocates `new` in
   persistent EEPROM and never collects it. Anything reachable from an APDU
   handler must use buffers allocated once at install
   (`JCSystem.makeTransientByteArray`).
   `SchnorrHWMathTest.noAllocationOutsideInstallTime` enforces this across every
   source under `applet/src/main/java/me/flashapp/cashu`. Each file needs an
   entry in that test's `INSTALL_TIME_METHODS` listing its install-time methods;
   a new file with no entry fails the test rather than going unchecked.
6. **Local checks must be at least as strict as the mint's.** The card burns a
   slot *before* the mint sees anything, so a check looser than the mint's
   passes locally and still costs the proof. See
   [D7](docs/DECISIONS.md#d7).

## Pull requests

1. Open an issue first for significant changes.
2. All PRs must pass CI.
3. Security-sensitive changes (key handling, spend logic, anything in
   `SchnorrHW`) require two reviewers.
4. Spec changes should be discussed in
   [cashubtc/nuts](https://github.com/cashubtc/nuts) before implementation.
5. **Do not claim testing you did not perform.** In a repo handling bearer
   funds, reviewers have to take those statements at face value.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md). Do not open a public issue for anything
affecting funds.
