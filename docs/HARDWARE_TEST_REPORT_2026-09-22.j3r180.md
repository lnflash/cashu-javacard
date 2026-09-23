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

## End-to-end load → spend → settle (2026-09-22)

The full bearer-card round trip was run against the project mint
`https://forge.flashapp.me` (Nutshell 0.20.3.1, NUT-11 + NUT-12): mint a proof
locked to the card, load it, spend it on the card, redeem it at the mint, and
return the change to the card. At no point does the host see the card's key.

```text
fund-card  → 16 sat quote paid → 1 proof, DLEQ verified
load-file  → slot 0 = 16 sat; balance 16
spend      → card marks slot 0 SPENT, returns BIP-340 signature over the NUT-11
             message; host attaches the witness
swap       → mint accepts the card's signature; input now SPENT
change     → 16 sat returned, relocked to the card key, loaded back to slot 1
```

| Step | Evidence |
|---|---|
| Load | `load-file`: `slot 0: 16 sat`; `balance` → `16` |
| Sign | `BIP-340 : VALID`; slot `unspent` → `spent` before the signature was returned |
| Redeem | `swap : OK — 1 blind signature(s)` |
| Double-spend | mint `checkstate`: input `SPENT`; change proof `UNSPENT` |
| Change | `slot 1: 16 sat`; final `balance` → `16`, slot 0 `spent`, slot 1 `unspent` |

This exercises `LOAD_PROOF`, `SPEND_PROOF` (spend-before-sign ordering), the
NUT-10 secret reconstruction, NUT-11 witness, and NUT-03/DLEQ on real silicon —
the applet, the card file, and the host client together.

## Not exercised

`clear-spent`, `set-pin`, `change-pin`, `lock` were not run (state-changing /
irreversible). The change proof was relocked to the card and reloaded rather
than melted, so a bolt11 melt (NUT-05) is also still unrun on silicon.
