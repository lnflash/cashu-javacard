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

The CAP tracked in this repo is **applet version 0.5**, sha256
`fdee73dc8422b14d326cbe679c4478ec24ba2614c905b4d0f47f97548aec18a4`. A CAP you
build yourself hashes differently even from identical source, because the
converter writes a creation timestamp into `META-INF/MANIFEST.MF`. Every other
entry is byte-identical when built with JDK 17 and the kit CI pins
(`jc305u4_kit` at `oracle_javacard_sdks` commit `6a75ec0d`), and CI checks
exactly that on every push. So before installing your own build, compare every
entry except `META-INF/MANIFEST.MF` against the tracked CAP:

```bash
# From applet/, after `ant cap` has overwritten target/cashu-javacard-0.1.0.cap
git show HEAD:applet/target/cashu-javacard-0.1.0.cap > /tmp/tracked.cap
rm -rf /tmp/cap-tracked /tmp/cap-built
unzip -q /tmp/tracked.cap -d /tmp/cap-tracked
unzip -q target/cashu-javacard-0.1.0.cap -d /tmp/cap-built
diff -r -x MANIFEST.MF /tmp/cap-tracked /tmp/cap-built && echo "same CAP as the tracked one"
```

Any output from `diff` means the two CAPs differ; do not install. After
installing, `SELECT` must answer `00 05` (below).

**Install only a CAP that matches the tracked one** (sha256 `fdee73dc…`, or the
entry comparison above). The file name and the CAP's package version read 0.1
on every build (`applet/build.xml` pins the package version), so neither can
tell a fixed build from a vulnerable one; only the applet version `SELECT`
answers after install can. Every 0.1 and 0.2 applet build carries ENG-615: its gate checks `pinState == 1`, so once the PIN is blocked,
`LOAD_PROOF`, `CLEAR_SPENT` and `LOCK_CARD` stop asking for it, and so do
`SPEND_PROOF` and `SIGN_ARBITRARY` on builds that gate them (0.1 builds from
before D13 gate no spend at all). The last tracked 0.2 CAP was sha256
`939cf24a…`. A card whose `SELECT` answers anything below `00 04` (`00 01`,
`00 02` or `00 03`) needs reinstalling — sweep its balance first (see
[Upgrade](#upgrade--re-personalise)).

A card answering `00 03` has the ENG-615 fix but may still carry ENG-620: a
card pulled mid-`LOAD_PROOF` can show a phantom proof ([D14](DECISIONS.md#d14)).
`main` tracked a 0.3 CAP with the old slot write order, sha256 `958a8baa…`,
from `f889934` (merged 2026-09-30) until the ENG-620 fix replaced it; no
release carries it. Nothing on an installed card tells it apart from a 0.3
build with the fix, which is why the fix moved the applet version to 0.4.
Don't install `958a8baa…` or any other 0.3 CAP.

A card answering `00 04` is sound: 0.4 fixed ENG-620 and 0.5 fixes nothing,
it adds `CLEAR_PIN` ([D15](DECISIONS.md#d15)), which a 0.4 card answers with
`6D00`. The last tracked 0.4 CAP was sha256 `d2947b9f…`. Reinstall a 0.4 card
only if its holder wants `CLEAR_PIN`, and like every version change that is a
fresh install — delete, then install — with the balance swept first, because
there is no in-place upgrade and the reinstall regenerates the card key (see
[Upgrade](#upgrade--re-personalise)). `cardctl selftest` passes a 0.4 card and
says it lacks `CLEAR_PIN`.

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

# Response: 0005 9000  (applet version 0.5 + SW_OK = applet responding)
# Anything below 0004 (0001, 0002 or 0003) may carry ENG-615 or ENG-620: sweep the card, then reinstall.
# 0004 is sound but has no CLEAR_PIN; reinstall only if wanted (sweep first).

# GET_INFO (INS 0x01)
gp --apdu B0010000

# Response: 00 05 20 00 00 20 0F 00
#   v0.5 | 32 slots | 0 unspent | 0 spent | 32 empty | caps=0x0F (bit 3 = CLEAR_PIN) | PIN unset
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

The applet has no OTA upgrade path — delete and reinstall to upgrade. That
includes 0.4 → 0.5 (`CLEAR_PIN`): there is no in-place upgrade, so a card
that should answer `0x43` is deleted and installed from the 0.5 CAP.
All proof data and the card keypair are wiped on delete, and the proofs are
P2PK-locked to that keypair, so **sweep the balance before deleting**. The
v0.2 reinstall on the J3R180 stranded 5 sat this way (see the
[hardware test report](HARDWARE_TEST_REPORT_2026-09-22.j3r180.md)).

For production cards, use a secure messaging channel (SCP02/SCP03) with the card's default keys. Contact the card vendor for production key ceremonies.

---

## Schnorr hardware path (SchnorrHW)

`SchnorrHW.java` implements BIP-340 using only `javacard.security.*`:

| Step | API used |
|------|----------|
| SHA-256 | `MessageDigest.ALG_SHA_256` |
| k·G scalar multiply | `KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY` |
| BIP-340 aux randomness | `RandomData.ALG_SECURE_RANDOM` |
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

### Install-time ECDH framing probe

`ALG_EC_SVDP_DH_PLAIN_XY` output framing is not uniform across implementations:
the applet reads a 65-byte `04 ‖ X ‖ Y`, and some parts return the bare 64-byte
`X ‖ Y` instead. `SchnorrHW.init()` therefore performs one throwaway `2·G` at
install time and refuses to install if the framing is not what `sign()` indexes
into.

If `gp --install` fails with `6F00`, that probe is the first thing to suspect —
and it failing there is the desired outcome. The alternative is discovering it
at spend time, where `SPEND_PROOF` marks the slot SPENT *before* signing: an
incompatible card would consume one proof per tap, return `6F00` each time, and
leave the proofs unredeemable because they are P2PK-locked to a key whose card
can no longer sign.

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
