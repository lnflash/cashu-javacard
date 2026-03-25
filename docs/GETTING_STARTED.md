# Getting Started with cashu-javacard

This guide walks you through everything you need to load the Cashu applet onto a physical JavaCard and start making offline NFC payments.

## What Is cashu-javacard?

**cashu-javacard** is a JavaCard applet that turns a physical NFC card into a Cashu ecash wallet. It implements the [Cashu](https://cashu.space) ecash protocol on a smart card chip, enabling **offline bearer payments** — the card holds Cashu proofs directly, and payments happen via NFC tap without internet access.

This is the reference implementation of **NUT-XX: Cashu NFC Card Protocol, Profile B (Bearer/Offline)**.

### How It Works

There are two phases: **top-up** (online) and **payment** (offline).

#### Top-Up Phase (Online)

```
You (with mobile app)
    │
    ▼
flash-mobile ──► Flash backend ──► forge.flashapp.me (Cashu mint)
                                       │
                                  Cashu proofs
                                       │
                                       ▼
                              NFC write to your JavaCard
```

1. You load funds via the [Flash mobile app](https://github.com/lnflash/flash-mobile) or a compatible Cashu wallet
2. The backend mints Cashu proofs (cryptographic tokens representing value)
3. Proofs are written to your card via NFC

#### Payment Phase (Offline)

```
Customer taps card at POS terminal
    │
    ▼
flash-pos reads proofs (no internet required)
    │
    ▼
Merchant verifies mint signature locally
    │
    ▼
Later (when online): flash-pos redeems proofs with forge.flashapp.me
```

1. You tap your card on a [Flash POS](https://github.com/lnflash/flash-pos) terminal
2. The POS reads your Cashu proofs directly from the card via NFC — **no internet needed**
3. The merchant's terminal verifies the mint's signature locally
4. Later, when online, the POS redeems the proofs at the mint

### Key Properties

- **Truly offline**: No phone, no internet, no battery required — just a card
- **Bearer instrument**: Whoever holds the card holds the value
- **Cryptographically secure**: secp256k1 on-chip key generation, Schnorr signing for NUT-11 P2PK
- **Spend protection**: Hardware-enforced non-resettable spend counter prevents double-spending
- **Persistent storage**: Proofs stored in EEPROM survive power loss

---

## Compatible Cards

| Chip | Status | Price | Notes |
|------|--------|-------|-------|
| Feitian JavaCard 3.0.4 | ✅ Target (v1) | ~$2/card in bulk | Primary target; full secp256k1 custom curve support |
| NXP JCOP4 SmartMX3 P71 | ✅ Target (v2) | ~$5/card | CC EAL 5+ certified; higher security |
| NXP NTAG 424 DNA | ❌ Not compatible | — | Insufficient memory, no EC crypto support |
| Generic JavaCard 3.0.1+ | ⚠️ May work | Varies | Verify `ALG_EC_SVDP_DH_PLAIN_XY` support first |
| JavaCard 2.2.x | ❌ Not compatible | — | Missing `int` type and ECDH plain-XY |

### Where to Buy

- **Feitian JavaCard 3.0.4**: Available from [Feitian](https://www.ftsafe.com/) or Alibaba. Look for "JavaCard 3.0.4" with NFC support.
- **NXP JCOP4 SmartMX3**: Available from NXP distributors (Digi-Key, Mouser). Higher security certification for production deployments.

> **Tip**: For development and testing, Feitian cards are recommended — they're cheap and widely supported.

---

## Prerequisites

You need the following tools installed:

| Tool | Version | Install |
|------|---------|---------|
| JDK | 11+ | `brew install openjdk@17` (macOS) or `apt install openjdk-17-jdk` (Debian/Ubuntu) |
| Apache Ant | 1.10+ | `brew install ant` (macOS) or `apt install ant` (Debian/Ubuntu) |
| GlobalPlatformPro | 20.01.23+ | See below |
| PC/SC reader | ISO 7816-4 compatible | `brew install pcsc-lite` (macOS) or `apt install pcscd libpcsclite-dev` (Debian/Ubuntu) |

### Install GlobalPlatformPro

GlobalPlatformPro (`gp`) is the tool used to install, manage, and interact with JavaCard applets.

```bash
# Download gp.jar
curl -L https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar \
     -o /usr/local/bin/gp.jar

# Create wrapper script
cat > /usr/local/bin/gp << 'EOF'
#!/bin/sh
exec java -jar /usr/local/bin/gp.jar "$@"
EOF
chmod +x /usr/local/bin/gp

# Verify installation
gp --help
```

---

## Step-by-Step: Loading the Applet onto a Card

### Step 1: Clone the Repository

```bash
git clone https://github.com/lnflash/cashu-javacard.git
cd cashu-javacard
```

### Step 2: Build the .cap File

The `.cap` file is the compiled JavaCard applet that gets loaded onto the card.

```bash
cd applet

# Build using ant (auto-downloads JavaCard SDK 3.0.4 on first run, ~40MB)
ant cap

# Output: target/cashu-javacard-0.1.0.cap
ls -lh target/cashu-javacard-0.1.0.cap
```

> **Important for hardware builds**: Before building, make sure the `HARDWARE` flag is set to `true` in `CashuApplet.java`:
> ```java
> static final boolean HARDWARE = true;
> ```
> This switches from simulation mode (jCardSim) to hardware mode (SchnorrHW with native secp256k1). If you forget this, the applet will not work on physical cards.

### Step 3: Connect Your Card Reader

1. Plug in your USB card reader (any ISO 7816-4 compatible reader works)
2. Insert your JavaCard into the reader
3. Verify the connection:

```bash
gp --list
```

Expected output for a fresh card:
```
ISD: A000000151000000 (OP_READY)
```

### Step 4: Install the Applet

```bash
# From the applet/ directory:
gp --install target/cashu-javacard-0.1.0.cap

# Verify installation
gp --list
```

Expected output after install:
```
APP: D276000085010201 (SELECTABLE)
```

### Step 5: Verify the Installation

Test that the applet is responding:

```bash
# SELECT the applet
gp --apdu 00A4040007D2760000850102
# Expected: 0000 9000  (version 0.0 + SW_OK)

# Get card info
gp --apdu B0010000
# Expected: 00 01 20 00 00 00 06 (v0.1, 32 slots, 0 unspent, 0 spent)

# Get the card's public key
gp --apdu B0100000
# Expected: 33-byte compressed secp256k1 public key + SW 9000
```

**Your card is now ready!** It has a unique secp256k1 keypair and 32 empty proof slots.

---

## Using the Card

### Top Up (Load Value onto Card)

Top-up requires the [Flash mobile app](https://github.com/lnflash/flash-mobile) connected to the [Flash backend](https://forge.flashapp.me):

1. Open Flash mobile app
2. Initiate a top-up (Lightning or on-chain)
3. Hold your card to the phone's NFC reader
4. The app writes Cashu proofs to the card via NFC
5. Check balance: `gp --apdu B0110000` returns the sum of unspent proof amounts

### Pay (Offline NFC Tap)

1. Merchant opens [Flash POS](https://github.com/lnflash/flash-pos)
2. You tap your card on the POS NFC reader
3. The POS reads proofs from the card (no internet needed)
4. POS verifies mint signatures locally
5. POS marks proofs as spent on the card (non-reversible)
6. Later, POS redeems proofs online at the mint

### Check Balance

```bash
gp --apdu B0110000
# Response: <4-byte uint32 balance in sats> 9000
```

### List Proofs

```bash
gp --apdu B0120000
# Response: <1-byte count> 9000
```

---

## Troubleshooting

### "No card found" or connection errors

- Ensure the card is fully inserted in the reader
- Try re-seating the card
- Check that `pcscd` (PC/SC daemon) is running: `systemctl status pcscd` (Linux)
- On macOS, ensure PCSC framework is installed: `brew install pcsc-lite`

### Build fails with "javacard not found"

- ant-javacard auto-downloads the SDK on first run — ensure you have internet access
- Check that `JAVA_HOME` is set: `echo $JAVA_HOME`
- Verify JDK 11+: `java -version`

### Applet install fails with "SW 6985" (Conditions not satisfied)

- The card may already have an applet with the same AID. Delete it first:
  ```bash
  gp --delete D276000085010201  # applet AID
  gp --delete D276000085010200  # package AID
  ```
- Some cards require secure messaging for install — check with your card vendor

### Card works in simulation but not on hardware

- Verify `HARDWARE = true` is set in `CashuApplet.java` before building
- Rebuild with `ant clean cap` after changing the flag
- The `SchnorrHW` implementation requires `ALG_EC_SVDP_DH_PLAIN_XY` — not all cards support this

---

## Further Reading

- [Architecture Guide](ARCHITECTURE.md) — On-card data model, key management, spend protection
- [Hardware Deployment Guide](HARDWARE_DEPLOYMENT.md) — Detailed build, install, and upgrade procedures
- [APDU Command Reference](../spec/APDU.md) — Full command set with byte-level details
- [NUT-XX Protocol Spec](../spec/NUT-XX.md) — The Cashu NFC Card Protocol specification
- [Contributing Guide](../CONTRIBUTING.md) — How to contribute to the project

---

## Related Projects

- [forge.flashapp.me](https://forge.flashapp.me) — Flash Cashu mint (Nutshell 18.0)
- [flash-pos](https://github.com/lnflash/flash-pos) — Merchant point-of-sale app
- [flash-mobile](https://github.com/lnflash/flash-mobile) — Customer mobile app
- [Cashu NUTs](https://github.com/cashubtc/nuts) — Cashu protocol specifications
