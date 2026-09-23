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

## NUT-05 melt on a Lightning invoice (2026-09-22)

The redeem path above settles through a NUT-03 swap. The real terminal settle is
a **melt**: hand the mint the card's proof and have its Lightning node pay an
invoice. Run with `tools/e2e-melt.cjs`:

```text
quotes      : invoice 16 sat + reserve 0 = needs 16 of 16
  card>     slot 2 before : unspent, amount 16
  card>     BIP-340   : VALID ✅
  card>     slot 2 after  : spent
melt        : quote 01a0cf72-… — 16 in, 0 back as change [none]
melt state  : PAID
recovered   : 1 minted + 0 change = 16 sat (net Lightning cost 0)
```

The invoice melted was a fresh mint quote at the same mint, so the payment is
verifiable in both directions: the melt returned `PAID` with a preimage, the
quote flipped `PAID` on the mint side, the paid value was minted back out,
relocked to the card key, and reloaded (`slot 3: 16 sat`). Card value moved
card → Lightning → card with zero loss — the mint charged no fee reserve on a
16-sat invoice.

This exercises NUT-05 quote + execute with a P2PK-locked input and witness, the
melt-amount-required check (the card burns its slot before the mint sees
anything, so an underfunded melt must be refused host-side), and quote-state
reconciliation after a non-idempotent payment.

## PIN + `CLEAR_SPENT` (2026-09-22)

The full authentication surface, on silicon (`PIN_MAX_TRIES = 3`, OwnerPIN
semantics — a successful verify resets the counter):

| Check | Result |
|---|---|
| `SET_PIN 1234` | set once; `GET_INFO` flips `PIN unset` → `set` |
| `VERIFY_PIN 9999` | `63C2` — wrong PIN, **2 retries remaining** |
| `VERIFY_PIN 1234` | verified; retry counter resets |
| `CHANGE_PIN 1234→5678` | old PIN invalid afterwards, new PIN verifies |
| `CHANGE_PIN 5678→1234` | restored |
| `CLEAR_SPENT` without PIN | `6982` — refused, nothing freed |
| `CLEAR_SPENT --pin 1234` | **3 slots freed** (0–2), balance 16 intact |
| `LOAD_PROOF` without a verified session | `6982` — refused before any write |

The write gate was probed at the APDU level (`b0300000` in a fresh session) to
confirm the applet's ordering: `requirePinIfSet()` is the first statement of
`processLoadProof`, so an unverified session cannot reach payload validation or
a slot write. Spends stay PIN-free by design — `SPEND_PROOF` sits in category
0x2x precisely because a bearer card must tap-to-pay with no PIN (spec, line
162–164); the e2e melt/redeem scripts therefore keep working with a PIN set.

Card left personalised: PIN `1234`, slots 0–2 reclaimed, slot 3 unspent (16 sat).

## First contact from the merchant terminal (2026-09-23)

The Flash POS spike (`lnflash/flash-pos` #67) — an *independent* implementation
of this spec's read path in TypeScript (`src/services/cashuCard.ts`) — ran
against this card over phone NFC: dev build on an iPhone 13 Pro Max (iOS 26.5),
IsoDep transport, entitlement `com.apple.developer.nfc.readersession.formats`
carrying `TAG`, AIDs `D2760000850102`/`D276000085010201` declared in
`Info.plist`.

`SELECT → GET_INFO → GET_PUBKEY → GET_BALANCE` all succeeded on the **first
hardware session**: applet version 0.1, balance 16 sat, public key
`03858498d50d2545…4d` — byte-identical to the key `cardctl` reads over the
ACR122U reference reader, on the same card, minutes apart.

Two things this proves:

- **The 33-byte fix held across implementations.** flash-pos's parser
  *requires* 33 bytes and was written against the spec without ever touching
  silicon; its fake-card tests could never have caught the old behaviour. The
  fixed applet is what made this first contact pass — the pre-fix applet
  (65-byte `getW()`) would have failed it, again.
- **Two independent implementations of one spec now agree on real hardware**
  (`cardctl`/Python over PC-SC; `cashuCard.ts`/TypeScript over CoreNFC). That
  is the differential check this project's docs ask for, done where drift
  costs money.

nfcd corroboration from the USB syslog: `_NFHardwareManager … startNextSession`
followed by `NFDriverNotifyDiscovery … tag removed` brackets the session; iOS
masks APDU payloads (`<private>`), so the on-screen values are the evidence of
record. Android remains unexercised.

## Not exercised

`lock` (permanently disables writes — deliberately not run on a card holding
value). Melting an *external* merchant invoice (rather than the self-referential
mint quote used here) differs only in the bolt11 supplied.
