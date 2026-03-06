# Contributing to cashu-javacard

This project is an open-source implementation of [NUT-XX: Cashu NFC Card Protocol](spec/NUT-XX.md) and welcomes community contributions. We follow the Cashu ecosystem's open-source ethos and meticulous review process.

## Development Setup

### Prerequisites

- JDK 11+
- JavaCard SDK 3.0.4+ ([Oracle](https://www.oracle.com/java/technologies/javacard-downloads.html))
- [jCardSim](https://jcardsim.org/) (for tests — no hardware required)
- Gradle 7+

### Running Tests

```bash
./gradlew test
```

All tests run against jCardSim — you don't need physical hardware to develop or test.

## Key Design Principles

1. **Security first**: The card's private key must never leave the chip. All sensitive operations happen on-chip.
2. **Hardware spend protection**: Spent proof slots must use non-resettable mechanisms. Never allow a spent proof to be unmarked.
3. **Spec alignment**: All commands and behavior must match NUT-XX exactly. If the spec is ambiguous, open a spec issue before implementing.
4. **Portability**: Applet should run on any JavaCard 3.0.4+ chip with secp256k1 support. Avoid chip-specific APIs.

## Pull Request Process

1. Open an issue first for significant changes
2. All PRs require passing jCardSim tests
3. Security-sensitive changes (key handling, spend logic) require two reviewers
4. Spec changes must be discussed in cashubtc/nuts before implementation
