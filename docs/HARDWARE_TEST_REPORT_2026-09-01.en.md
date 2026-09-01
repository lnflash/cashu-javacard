# Cashu JavaCard Physical Hardware Test Report

- **Test date:** 2026-09-01 (UTC+08:00)
- **Repository commit:** `afe1081220663f66b8fc9e8445800e599672e849`
- **Scope:** Host-side tests, reader discovery, physical-card `selftest`, and safe read/sign commands documented in `tools/cardctl/README.md`
- **Overall result:** The applet's core physical-hardware functionality passed. The unmodified `cardctl selftest` and `cardctl sign` commands terminate with an exception because the physical card returns a 65-byte uncompressed public key, exposing a public-key encoding incompatibility between the applet, specification, and host tool.

## 1. Executive summary

The test was performed on a Windows 11 host using the PICC interface of an ACS ACR1281 reader and a physical JavaCard based on an **NXP JCOP4.5 J3R452** chip, on which the Cashu applet was already installed.

The test confirmed that:

- the applet can be selected by AID;
- `GET_INFO`, `GET_BALANCE`, and `GET_SLOT_STATUS` work correctly;
- the public key returned by the card is a valid secp256k1 curve point;
- signatures produced by `SIGN_ARBITRARY` verify under BIP-340;
- two signatures over the same message use different `R` values, with no observed nonce reuse;
- all four reader-independent tests listed in the README pass; and
- no proof-writing, proof-spending, PIN-changing, or card-locking operation was performed.

The unmodified `cardctl` commands cannot fully process this card. `GET_PUBKEY` returns a 65-byte public key beginning with `0x04`, while the specification and host tool require a 33-byte compressed public key. To distinguish a host-format problem from a card cryptography failure, an additional hardware test normalized the public key on the host. All cryptographic checks passed.

## 2. Test environment

| Item | Value |
|---|---|
| Operating system | Microsoft Windows 11 Pro, 64-bit, version `10.0.26200`, build `26200` |
| Python | `3.13.15` |
| pyscard | `2.3.1` |
| Virtual environment | `tools/cardctl/.venv` |
| Test card chip | `NXP JCOP4.5 J3R452` |
| Reader | `ACS ACR1281 1S Dual Reader PICC 0` |
| cardctl reader index | `1` |
| Docker image | `cirne/javacard-great-again:latest` |
| Docker image ID | `sha256:6b4a0602999ab37e14d3fece86333e69c8312d1ceb420014e509537987f2a629` |
| Applet version | `0.1` |
| Package AID | `D2760000850102` |
| Applet AID | `D276000085010201` |

### CAP build artifact

| Item | Value |
|---|---|
| File | `applet/target/cashu-javacard-0.1.0.cap` |
| Size | `30,499` bytes |
| SHA-256 | `708FB76870F885B544F215C12BDD46445868A5BD4E2186B1F1DAB441ADE35E79` |
| Docker build result | `BUILD SUCCESSFUL` |
| CAP verification | `passed` |

Build command:

```powershell
docker run --rm `
  -v "C:\Users\richa\Documents\github\cashu-javacard:/workspace/cashu-javacard" `
  -v "C:\Users\richa\Documents\github\SatochipApplet\sdks\jc305u4_kit:/opt/jc305u4_kit:ro" `
  cirne/javacard-great-again:latest `
  sh -lc "cd /workspace/cashu-javacard/applet; ant cap -Djc.sdk=/opt/jc305u4_kit"
```

## 3. Safety boundary

Following `tools/cardctl/README.md`, this test only used commands that are read-only or expected to be safe for test signatures:

- `readers`
- `selftest`
- `info`
- `pubkey`
- `balance`
- `slots --all`
- `sign`

The following commands were deliberately not executed:

- `load` / `load-file`, because they write proofs;
- `spend`, because it irreversibly marks a proof as spent;
- `clear-spent`, because it modifies card storage;
- `set-pin` / `change-pin`, because they change authentication state; and
- `lock`, because it permanently disables writes and cannot be reversed.

All card-facing commands were executed serially. No concurrent APDUs were sent to the reader.

## 4. Host-side tests

The following commands were run from `tools/cardctl`:

```powershell
.\.venv\Scripts\python.exe .\test_bip340.py
.\.venv\Scripts\python.exe .\test_apdu.py
.\.venv\Scripts\python.exe .\test_spec_consistency.py
.\.venv\Scripts\python.exe .\test_card_file.py
```

Results:

| Test | Result | Coverage |
|---|---|---|
| `test_bip340.py` | PASS | BIP-340 specification vectors, reference-signer round trip, mutation rejection, and public-key handling |
| `test_apdu.py` | PASS | APDU encoding, response parsing, status words, and argument validation |
| `test_spec_consistency.py` | PASS | Consistency among `cardctl`, applet constants, and `spec/APDU.md` |
| `test_card_file.py` | PASS | Card File format, field validation, spent-proof safety, duplicate proofs, and curve-point checks |

All four suites reported:

```text
all tests passed
```

## 5. Reader discovery

Command:

```powershell
.\.venv\Scripts\python.exe .\cardctl.py readers
```

Output:

```text
[0] ACS ACR1281 1S Dual Reader ICC 0
[1] ACS ACR1281 1S Dual Reader PICC 0
[2] ACS ACR1281 1S Dual Reader SAM 0
```

The physical card was accessed through reader index `1`.

## 6. Unmodified cardctl physical-hardware test

Command:

```powershell
.\.venv\Scripts\python.exe .\cardctl.py -r 1 -v selftest
```

Successful checks:

```text
PASS  SELECT applet — version 0.1
PASS  GET_INFO — v0.1, 32 slots, PIN unset
PASS  Schnorr capability advertised — caps=0x07
PASS  GET_BALANCE — 0
PASS  GET_SLOT_STATUS — 32 status bytes
```

SELECT APDU:

```text
> 00a4040007d2760000850102
< 0001 9000
```

Decoded `GET_INFO` result:

```text
version       : 0.1
max slots     : 32
unspent       : 0
spent         : 0
empty         : 32
capabilities  : 0x07
PIN state     : unset
balance       : 0
```

Capability byte `0x07` advertises native secp256k1 keys, Schnorr signatures, and PIN support.

### 6.1 Failure point: GET_PUBKEY encoding mismatch

Request and response:

```text
> b010000021
< 042f3253009b4481805ae7b87e46fcc0b1a469b9e510fd1d9767bf146fb61abec8987303f74519a22b0c75d9cccee43ae61025d018c28fb5be47a1de35cfdad628 9000
```

The response is a 65-byte uncompressed secp256k1 public key with a `0x04` prefix. `cardctl selftest` reports:

```text
FAIL  GET_PUBKEY well-formed — 042f3253009b4481805a… (65 bytes)
```

It then terminates while attempting BIP-340 verification:

```text
ValueError: not a compressed secp256k1 pubkey: 65 bytes
```

The unmodified `selftest` therefore exits with status `1`.

### 6.2 Unmodified sign command

Command:

```powershell
.\.venv\Scripts\python.exe .\cardctl.py -r 1 -v sign
```

The card successfully returns a 64-byte signature with status word `9000`. The command then raises the same exception when it reads the 65-byte public key and calls `bip340.x_only()`.

Therefore:

- the signing APDU succeeds;
- unmodified `cardctl sign` fails during host-side verification; and
- the failure occurs in public-key format handling, not because the card rejects the signature request.

## 7. Safe read-only checks

### 7.1 info

```text
applet version   : 0.1
slots            : 32 total — 0 unspent, 0 spent, 32 empty
capabilities     : 0x07 (secp256k1 native=True, schnorr=True)
PIN              : unset
balance          : 0
```

Result: **PASS**

### 7.2 pubkey

```text
042f3253009b4481805ae7b87e46fcc0b1a469b9e510fd1d9767bf146fb61abec8987303f74519a22b0c75d9cccee43ae61025d018c28fb5be47a1de35cfdad628
```

Result: the key is read successfully, but it is encoded as a 65-byte uncompressed point rather than the specified 33-byte compressed form.

### 7.3 balance

```text
0
```

Result: **PASS**

### 7.4 slots --all

```text
32 slots (0 non-empty)
```

Slots `[0]` through `[31]` are all `empty`.

Result: **PASS**

## 8. Compatibility verification for the 65-byte key

To confirm that the observed failure was only a host-format limitation, an additional compatibility test performed the following steps:

1. accepted the 65-byte `0x04 || X || Y` public key;
2. checked that `(X, Y)` satisfies the secp256k1 curve equation;
3. extracted `X` as the BIP-340 x-only public key;
4. called `SIGN_ARBITRARY` for three random 32-byte messages;
5. verified every signature with the repository's `bip340.verify()` implementation; and
6. signed one random message twice, verified both signatures, and compared the first 32-byte `R` values.

Results:

```text
Public key point on secp256k1: True
SIGN_ARBITRARY + BIP-340 verify [1/3]: PASS
SIGN_ARBITRARY + BIP-340 verify [2/3]: PASS
SIGN_ARBITRARY + BIP-340 verify [3/3]: PASS
Identical-message signature #1 verifies: PASS
Identical-message signature #2 verifies: PASS
Fresh nonce across identical messages: PASS
MANUAL HARDWARE SELFTEST: PASS
```

These results demonstrate that:

- the physical card returns a valid secp256k1 public key;
- the card's private key matches the returned public key;
- Schnorr signatures produced by the card satisfy BIP-340;
- repeated signatures over the same message do not reuse `R`; and
- the applet's core signing functionality works correctly.

## 9. Defect analysis

### 9.1 Expected behavior

`spec/APDU.md`, `spec/NUT-XX.md`, `spec/CARD-FILE.md`, `docs/HARDWARE_DEPLOYMENT.md`, and `tools/cardctl/README.md` define `GET_PUBKEY` as returning a 33-byte compressed secp256k1 public key.

### 9.2 Actual behavior

The tested physical card returns a 65-byte uncompressed public key. The current implementation contains the following inconsistency:

- `CashuApplet.processGetPubkey()` sends the result of `cardPubKey.getW()` directly, without compression;
- this card's `ECPublicKey.getW()` returns a 65-byte uncompressed point;
- `CashuAppletTest.testGetPubkey()` permits either 33 or 65 bytes;
- `cardctl.Card.get_pubkey()` and `bip340.x_only()` support only the specified compressed representation; and
- `cardctl selftest` does not convert the unsupported encoding into a clean test failure and instead prints a Python traceback.

### 9.3 Impact

- `cardctl selftest` cannot complete on this physical card;
- `cardctl sign` cannot complete host-side signature verification;
- `cardctl pubkey` outputs a value that does not satisfy the Card File requirement for a 33-byte compressed key;
- using this output to construct a NUT-11 P2PK secret or Card File may cause interoperability failures; and
- the README assumption that physical hardware returns a compressed public key does not hold for the tested card.

### 9.4 Recommended fix

Preferred specification-conforming fix:

1. in the applet's `processGetPubkey()`, compress `0x04 || X || Y` returned by `getW()` into `0x02/0x03 || X`;
2. always return exactly 33 bytes;
3. tighten the applet test from “33 or 65 bytes” to “33 bytes only”; and
4. run the regression suite under both jCardSim and physical hardware.

Additional defensive host-side compatibility is recommended:

1. allow `cardctl` to recognize a valid 65-byte uncompressed point;
2. validate that the point lies on secp256k1 and normalize it to the 33-byte compressed representation;
3. allow `bip340.x_only()` to safely extract X from a valid compressed or uncompressed point;
4. make `selftest` report an unsupported encoding as a clear FAIL instead of a traceback; and
5. add regression tests for a 65-byte hardware response.

Host-side compatibility should not replace the applet fix because the protocol and Card File format explicitly require the 33-byte compressed representation.

## 10. Result matrix

| Test item | Result |
|---|---|
| CAP build | PASS |
| CAP verification | PASS |
| Four README host-side test suites | PASS |
| PC/SC reader discovery | PASS |
| SELECT applet | PASS |
| GET_INFO | PASS |
| GET_BALANCE | PASS |
| GET_SLOT_STATUS | PASS |
| GET_PUBKEY APDU | PASS, returned `9000` |
| GET_PUBKEY specified encoding | FAIL, returned a 65-byte uncompressed key |
| Unmodified `cardctl selftest` | FAIL, public-key format exception and traceback |
| Unmodified `cardctl sign` | FAIL, public-key format exception and traceback |
| Public-key secp256k1 curve validation | PASS |
| Three physical-card BIP-340 signature checks | PASS |
| Two signatures over an identical message | PASS |
| Nonce/R non-reuse check | PASS |
| `info` / `balance` / `slots --all` | PASS |
| Destructive or state-changing commands | Not executed |

## 11. Conclusion

The applet is installed correctly and runs on the physical JavaCard. Applet selection, status reads, slot-status reads, and the hardware Schnorr signing path work correctly. BIP-340 verification and nonce-freshness checks pass.

The test also identified a reproducible public-key encoding interoperability defect: the physical card's `ECPublicKey.getW()` returns a 65-byte uncompressed point, while the protocol and `cardctl` require a 33-byte compressed point. This should be reported as an applet/host interoperability issue. The preferred resolution is to make the applet strictly return the specified compressed public key, together with defensive normalization and clearer error handling in the host tool.
