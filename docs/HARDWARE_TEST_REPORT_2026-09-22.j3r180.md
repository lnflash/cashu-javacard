# On-silicon test report — NXP JCOP4 J3R180 P71 (2026-09-22)

First successful run of the applet on physical hardware. The signing path,
`GET_PUBKEY` encoding, and signature nonce freshness all verify on real silicon.

## Card

| Item | Value |
|---|---|
| Chip | NXP JCOP4 J3R180 P71 (SECID) |
| ATR | `3B 8A 80 01 4A 54 61 78 43 6F 72 65 56 31 50` |
| JavaCard | 3.0.5 (matches JCAlgTest profile `c71`) |
| GlobalPlatform | 2.3, SCP02 |
| ISD | `A000000151000000` (OP_READY), **default keys** (`4041..4F`) |
| Interface | contactless (NFC) |

This is the card Satochip recommends and the one `docs/HARDWARE_DEPLOYMENT.md`
requires (JavaCard 3.0.5+, `ALG_EC_SVDP_DH_PLAIN_XY`, dual-interface, unlocked).

## Environment

| Item | Value |
|---|---|
| Reader | ACS ACR122U PICC (contactless) |
| Host | macOS 26.5 (aarch64), Java 17 |
| GlobalPlatformPro | v25.10.20 |
| Applet CAP | `applet/target/cashu-javacard-0.1.0.cap`, sha256 `c529006f…` |
| Tool | `cardctl selftest` (this repo) |

## Result: `cardctl selftest` — all 10 checks passed

```text
reader: ACS ACR122U PICC Interface

PASS  SELECT applet  — version 0.1
PASS  GET_INFO  — v0.1, 32 slots, PIN unset
PASS  Schnorr capability advertised  — caps=0x07
PASS  GET_PUBKEY well-formed  — 03858498d50d2545aec9… (33 bytes, compressed)
PASS  GET_BALANCE  — 0
PASS  GET_SLOT_STATUS — 32 status bytes
PASS  SIGN_ARBITRARY + BIP-340 verify [1/3]
PASS  SIGN_ARBITRARY + BIP-340 verify [2/3]
PASS  SIGN_ARBITRARY + BIP-340 verify [3/3]
PASS  fresh nonce across identical messages
```

### Notable

- `GET_PUBKEY` returned a **33-byte compressed** key (`03…`) — the fix in #23.
  On this same JCOP4 family the raw `ECPublicKey.getW()` is 65 bytes, which
  previously crashed `selftest`/`sign` (#22). The normalisation is now proven
  on hardware, not just in the simulator.
- Three independent `SIGN_ARBITRARY` signatures verify under BIP-340.
- Two signatures over an identical message use a different `R`, so aux
  randomness works — no nonce reuse.

## Not exercised

`load`, `load-file`, `spend`, `clear-spent`, `set-pin`, `change-pin`, `lock`
were not run (state-changing / irreversible). `sign` does not consume a proof.
