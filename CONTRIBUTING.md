# Contributing to cashu-javacard

This project is an open-source implementation of [NUT-XX: Cashu NFC Card Protocol](spec/NUT-XX.md) and welcomes community contributions. We follow the Cashu ecosystem's open-source ethos and meticulous review process.

## Development Setup

### Prerequisites

- JDK 11+
- Maven 3.8+ (tests) and Apache Ant 1.10+ (CAP build)
- JavaCard SDK 3.0.5+ — `git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/.javacard/sdks`
  (3.0.4 is **not** sufficient: `ALG_EC_SVDP_DH_PLAIN_XY` is 3.0.5+)
- jCardSim (pulled in by Maven; no hardware required for tests)

### Running Tests

```bash
mvn -f applet/pom.xml test
```

All tests run against jCardSim — you don't need physical hardware to develop or test.

### Building the CAP

```bash
ant -f applet/build.xml cap
```

CI runs both on every push: the test suite on JDK 11 and 17, and the CAP
conversion. A change that breaks either is caught there.

## Key Design Principles

1. **Security first**: The card's private key must never leave the chip. All sensitive operations happen on-chip.
2. **Hardware spend protection**: Spent proof slots must use non-resettable mechanisms. Never allow a spent proof to be unmarked.
3. **Spec alignment**: All commands and behavior must match NUT-XX exactly. If the spec is ambiguous, open a spec issue before implementing.
4. **Portability**: Applet should run on any JavaCard 3.0.5+ chip with secp256k1 support. Avoid chip-specific APIs.
5. **No allocation after install**: JavaCard Classic allocates `new` in persistent EEPROM/Flash and never collects it. Anything reachable from an APDU handler must use buffers allocated once at install time (`JCSystem.makeTransientByteArray`). `SchnorrHWMathTest.noAllocationOutsideInstallTime` enforces this for the signer.

## Pull Request Process

1. Open an issue first for significant changes
2. All PRs require passing jCardSim tests
3. Security-sensitive changes (key handling, spend logic) require two reviewers
4. Spec changes must be discussed in cashubtc/nuts before implementation
