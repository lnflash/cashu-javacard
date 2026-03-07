# Hardware Deployment Guide

ENG-182 — GlobalPlatform packaging and deployment for CashuApplet.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Java | 11+ | `brew install openjdk@17` |
| Apache Ant | 1.10+ | `brew install ant` |
| GlobalPlatformPro (gp) | 20.01.23+ | See below |
| Physical card | Feitian JavaCard 3.0.4 *or* NXP JCOP4 SmartMX3 | |
| PC/SC reader | Any ISO 7816-4 reader | `brew install pcsc-lite` |

### Install GlobalPlatformPro

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
```

---

## Build the .cap file

```bash
cd cashu-javacard/applet

# Build (ant-javacard auto-downloads JavaCard SDK 3.0.4 on first run)
ant cap

# Output: target/cashu-javacard-0.1.0.cap
ls -lh target/cashu-javacard-0.1.0.cap
```

> **First run**: ant-javacard will download the JavaCard 3.0.4 SDK
> from GitHub (~40 MB). Subsequent builds use the cached SDK.

### Switch to hardware Schnorr before building

In `CashuApplet.java`, set the hardware flag:

```java
// Before: simulation mode (jCardSim / tests)
static final boolean HARDWARE = false;

// For .cap build: hardware mode (SchnorrHW, no BigInteger)
static final boolean HARDWARE = true;
```

Then build:
```bash
ant clean cap
```

---

## Connect and verify card

```bash
# Insert card into reader, then:
gp --list

# Expected output (fresh card):
# ISD: A000000151000000 (OP_READY)
```

---

## Install

```bash
# Install CashuApplet.cap onto the card
gp --install target/cashu-javacard-0.1.0.cap

# Verify installation
gp --list
# Expected:
#   APP: D276000085010201 (SELECTABLE)   ← our applet
```

---

## Test install / select / deselect lifecycle

```bash
# SELECT the applet (sends SELECT APDU with our AID)
gp --apdu 00A4040007D2760000850102

# Response: 0000 9000  (version 0.0 + SW_OK = applet responding)

# GET_INFO (INS 0x01)
gp --apdu B0010000

# Response: 00 01 20 00 00 00 06   (v0.1, 32 slots, 0 unspent, 0 spent, cap=0x06)
# SW: 9000

# GET_PUBKEY (INS 0x10)
gp --apdu B0100000

# Response: 33-byte compressed secp256k1 public key + SW 9000
```

---

## Reinstall (delete + install)

```bash
# Delete the applet (and its package)
gp --delete D276000085010201   # applet AID
gp --delete D276000085010200   # package AID (optional)

# Re-install
gp --install target/cashu-javacard-0.1.0.cap
```

---

## Upgrade / re-personalise

The applet has no OTA upgrade path — delete and reinstall to upgrade.
All proof data and the card keypair are wiped on delete.

For production cards, use a secure messaging channel (SCP02/SCP03) with the card's default keys. Contact the card vendor for production key ceremonies.

---

## Schnorr hardware path (SchnorrHW)

`SchnorrHW.java` implements BIP-340 using only `javacard.security.*`:

| Step | API used |
|------|----------|
| SHA-256 | `MessageDigest.ALG_SHA_256` |
| k·G scalar multiply | `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` |
| 256-bit mulModN | Schoolbook 256×256 + 2-level DELTA reduction |
| 256-bit addModN | Carry-propagation + conditional subtract |

DELTA = 2^256 mod n = `0x00...01 45512319 50B75FC4 402DA173 2FC9BEBF`

The signing operation allocates ~192 bytes of heap during execution.
Pre-allocate proof: the applet's `scratch` buffer covers transient needs.

---

## Supported targets

| Card | JC API | Notes |
|------|--------|-------|
| Feitian JavaCard 3.0.4 | 3.0.4 | ✅ Primary target; secp256k1 custom curve supported |
| NXP JCOP4 SmartMX3 P71 | 3.0.4 | ✅ v2 target; same API set |
| Generic JC 3.0.1+ | 3.0.1 | ⚠️  May work; verify `ALG_EC_SVDP_DH_PLAIN_XY` support |
| JavaCard 2.2.x | 2.2 | ❌ No `int` type; no ECDH plain-XY |

---

## AID reference

| Element | AID (hex) |
|---------|-----------|
| Package | `D2 76 00 00 85 01 02` |
| Applet  | `D2 76 00 00 85 01 02 01` |
| SELECT  | `00 A4 04 00 07 D2 76 00 00 85 01 02` |
