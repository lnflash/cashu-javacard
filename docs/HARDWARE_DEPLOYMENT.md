# Hardware Deployment Guide

ENG-182 — GlobalPlatform packaging and deployment for CashuApplet.

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Java | 11+ | `brew install openjdk@17` |
| Apache Ant | 1.10+ | `brew install ant` |
| GlobalPlatformPro (gp) | 20.01.23+ | See below |
| JavaCard SDK | 3.0.5+ (`jc305u4_kit`) | See [Build the .cap file](#build-the-cap-file) |
| Physical card | NXP JCOP4 SmartMX3 (JavaCard 3.0.5+) | **Not** JavaCard 3.0.4 — see [Supported targets](#supported-targets) |
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

ant-javacard does **not** download JavaCard SDKs — you have to supply the kit
yourself and point `jc.sdk` at it. One clone covers every SDK version:

```bash
# One-time: fetch the JavaCard SDK kits (~200 MB, all versions)
git clone https://github.com/martinpaljak/oracle_javacard_sdks ~/.javacard/sdks
```

```bash
cd cashu-javacard/applet

# Build. jc.sdk defaults to ~/.javacard/sdks/jc305u4_kit; override if you
# cloned elsewhere. It must be a 3.0.5 (or later) kit — see below.
ant cap
ant cap -Djc.sdk=/path/to/jc305u4_kit   # explicit form

# Output: target/cashu-javacard-0.1.0.cap
ls -lh target/cashu-javacard-0.1.0.cap
```

> **3.0.5 is a hard floor.** `SchnorrHW` performs the `k·G` scalar multiply with
> `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, which was introduced in JavaCard 3.0.5
> and does not exist in 3.0.4. A 3.0.4 kit cannot convert this applet, and a
> 3.0.4 card cannot run it.

There is no build-time mode switch. `SchnorrHW` is the only signer; the
BigInteger simulation that used to sit behind a `HARDWARE` flag has been removed
(it could never be converted to a `.cap` — the JavaCard runtime has no
`java.math`).

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

# Response: 00 01 20 00 00 20 07 00
#   v0.1 | 32 slots | 0 unspent | 0 spent | 32 empty | caps=0x07 | PIN unset
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

The signing operation allocates **nothing** at runtime. JavaCard Classic puts
`new` in persistent EEPROM/Flash and never collects it, so an allocation on the
signing path would leak a few hundred bytes per tap until the card ran out of
persistent memory and every `SPEND_PROOF` / `SIGN_ARBITRARY` threw. All scratch
is allocated once at install time as `CLEAR_ON_DESELECT` transient arrays:
`sc` (256 B) plus `work` (288 B), threaded through the arithmetic helpers as
explicit `(work, workOff)` parameters.

---

## Supported targets

| Card | JC API | Notes |
|------|--------|-------|
| NXP JCOP4 SmartMX3 P71 | 3.0.5 | ✅ Primary target; secp256k1 custom curve supported |
| Feitian JavaCard 3.0.4 | 3.0.4 | ❌ No `ALG_EC_SVDP_DH_PLAIN_XY` (3.0.5+ only) — the CAP will not convert or load |
| Generic JC 3.0.5+ | 3.0.5 | ⚠️  May work; verify custom EC-FP curve + `ALG_EC_SVDP_DH_PLAIN_XY` support |
| JavaCard ≤ 3.0.4 | ≤ 3.0.4 | ❌ No ECDH plain-XY |
| JavaCard 2.2.x | 2.2 | ❌ No `int` type; no ECDH plain-XY |

---

## AID reference

| Element | AID (hex) |
|---------|-----------|
| Package | `D2 76 00 00 85 01 02` |
| Applet  | `D2 76 00 00 85 01 02 01` |
| SELECT  | `00 A4 04 00 07 D2 76 00 00 85 01 02` |
