# cashu-javacard

A JavaCard applet implementing the [Cashu](https://cashu.space) ecash protocol
for **offline NFC bearer payments** — a physical card that holds Bitcoin-
denominated ecash on its own chip and spends it by tapping, with no phone, no
account, and no internet at the point of sale.

Reference implementation of **NUT-XX: Cashu NFC Card Protocol**, Profile B
(Bearer/Offline).

> ### Status: R&D — no card has run this yet
>
> The applet builds into a verified CAP and its cryptography is correct **in
> simulation**. It has never executed on physical silicon, and there is **no
> merchant terminal software** — `flash-pos` contains no Cashu code today.
> Two bugs found in review were invisible to the simulator and would each have
> been fatal in the field. Read [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md)
> before trusting anything here with money.

## Start here

| You are… | Read, in order |
|---|---|
| **Curious what this is** | [`docs/VISION.md`](docs/VISION.md) |
| **A developer joining the project** | [`VISION`](docs/VISION.md) → [`ARCHITECTURE`](docs/ARCHITECTURE.md) → [`DECISIONS`](docs/DECISIONS.md) → [`CONTRIBUTING`](CONTRIBUTING.md) |
| **An AI agent working in this repo** | [`ARCHITECTURE`](docs/ARCHITECTURE.md) → [`DECISIONS`](docs/DECISIONS.md) → [`GLOSSARY`](docs/GLOSSARY.md). The decisions file exists so settled calls are not re-litigated. |
| **Auditing security** | [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) |
| **New to Cashu or smartcards** | [`docs/GLOSSARY.md`](docs/GLOSSARY.md) |
| **Holding a card and a reader** | [`tools/cardctl/README.md`](tools/cardctl/README.md) |
| **Manufacturing the card** | [`flash-card-assets`](https://github.com/lnflash/flash-card-assets) |

## The system

Five components; only the first three live in this repo.

| Component | Where | Status |
|---|---|---|
| **Applet** — card firmware | `applet/` | Builds, CI green, unproven on hardware |
| **cardctl** — PC/SC host driver | `tools/cardctl/` | Works; untested against a card |
| **Spec** — NUT-XX + APDU | `spec/` | Draft, not yet submitted upstream |
| **cashu-client** — mint protocol | [lnflash/cashu-client](https://github.com/lnflash/cashu-client) | Load + redeem implemented |
| **Card artwork** | [lnflash/flash-card-assets](https://github.com/lnflash/flash-card-assets) | Draft v1 |
| **Flash Forge** — the mint | [forge.flashapp.me](https://forge.flashapp.me) | **Live**, [reserves published](https://forge.flashapp.me/reserves) |
| **Merchant terminal** | — | ❌ **does not exist** |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the trust boundaries and
the two end-to-end flows.

## What the card does

- **Stores proofs** — 32 slots × 78 bytes in EEPROM
- **Holds a secp256k1 key** generated on-card at install, never exported
- **Signs** a 32-byte message with BIP-340 Schnorr, to unlock NUT-11 P2PK proofs
- **Marks a slot spent** before releasing the signature, irreversibly

What it does **not** do: any BDHKE (blinding/unblinding), any mint
communication, or any verification of what it is asked to sign. Those live on
the host — see [D3](docs/DECISIONS.md#d3).

## Supported hardware

| Chip | Status | Notes |
|---|---|---|
| NXP JCOP4 (SmartMX3) | ✅ Target | JavaCard 3.0.5, CC EAL 5+, ~$5/card |
| Feitian / JCOP3 JavaCard 3.0.4 | ❌ | No `ALG_EC_SVDP_DH_PLAIN_XY` — 3.0.5+ only |
| NXP NTAG 424 DNA | ❌ | No EC crypto; this is the BoltCard chip |

**JavaCard 3.0.5 or later is a hard requirement.** The signer computes `k·G`
with `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, which does not exist in the 3.0.4
API — verified against the SDK jars. The card must also be **dual-interface**
and supplied **unlocked** (known GlobalPlatform keys), or the applet can never
be installed. See [D6](docs/DECISIONS.md#d6).

## APDU command set

Full reference: [`spec/APDU.md`](spec/APDU.md).

| CLA | INS | Command | PIN | Description |
|---|---|---|---|---|
| `00` | `A4` | SELECT | — | ISO SELECT by AID |
| `B0` | `01` | GET_INFO | — | Version, slot counts, capabilities, PIN state |
| `B0` | `10` | GET_PUBKEY | — | 33-byte compressed public key |
| `B0` | `11` | GET_BALANCE | — | Sum of unspent amounts (uint32) |
| `B0` | `12` | GET_PROOF_COUNT | — | Count of non-empty slots |
| `B0` | `13` | GET_PROOF | — | Full proof at a slot index |
| `B0` | `14` | GET_SLOT_STATUS | — | One status byte per slot |
| `B0` | `20` | SPEND_PROOF | — | Mark spent + return 64-byte signature |
| `B0` | `21` | SIGN_ARBITRARY | — | Sign 32 bytes, consuming no proof |
| `B0` | `30` | LOAD_PROOF | ✔ | Store a proof in the next free slot |
| `B0` | `31` | CLEAR_SPENT | ✔ | Reclaim spent slots |
| `B0` | `40`–`42` | VERIFY/SET/CHANGE_PIN | — / ✔ | PIN management |
| `B0` | `50` | LOCK_CARD | ✔ | Irreversibly disable writes |

**Spending requires no PIN.** That is bearer semantics and the design's sharpest
edge — a hostile reader in range can drain a card. See
[D12](docs/DECISIONS.md#d12).

**AID:** package `D2 76 00 00 85 01 02`, applet `…02 01`.

## Build

Requires **JDK 11+** and a JavaCard SDK **3.0.5 or later**. The SDK is not
downloaded for you:

```bash
git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/.javacard/sdks

ant -f applet/build.xml cap
# → applet/target/cashu-javacard-0.1.0.cap
```

Override the kit with `-Djc.sdk=/path/to/jc305u4_kit`. Installing onto a card:
[`docs/HARDWARE_DEPLOYMENT.md`](docs/HARDWARE_DEPLOYMENT.md).

## Test

```bash
mvn -f applet/pom.xml test        # applet — jCardSim, no hardware needed
cd tools/cardctl && python3 test_bip340.py && python3 test_apdu.py
```

CI runs both on every push. **A green suite is not evidence about silicon** —
jCardSim runs on the JVM with a garbage collector and cannot reproduce EEPROM
exhaustion or hardware crypto framing. See [D10](docs/DECISIONS.md#d10).

## Project layout

```
applet/src/main/java/   applet source (JavaCard 3.0.5+)
applet/src/test/java/   jCardSim test suite
tools/cardctl/          PC/SC host driver + its own tests
spec/                   NUT-XX.md (protocol), APDU.md (wire format),
                        CARD-FILE.md (host↔mint interchange format)
docs/                   vision, architecture, decisions, security, glossary
```

## Spec

[`spec/NUT-XX.md`](spec/NUT-XX.md) is a draft, intended for submission to
[cashubtc/nuts](https://github.com/cashubtc/nuts) once it has run on hardware.
Profile A is an online, BoltCard-compatible mode; **Profile B** is what this
repo implements.

## Related

- [cashu-client](https://github.com/lnflash/cashu-client) — mint protocol, BDHKE, witnesses, DLEQ
- [flash-card-assets](https://github.com/lnflash/flash-card-assets) — print-ready physical card design
- [forge.flashapp.me](https://forge.flashapp.me) — the Flash Cashu mint ([reserves](https://forge.flashapp.me/reserves))
- [Numo](https://github.com/cashubtc/Numo) — Android Cashu NFC PoS, a Profile A reference
- [cashubtc/nuts](https://github.com/cashubtc/nuts) — the Cashu specifications

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/DECISIONS.md`](docs/DECISIONS.md) first — most of what looks like a
missing feature is a decision with reasoning behind it.

## License

MIT
