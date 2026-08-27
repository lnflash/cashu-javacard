# cardctl — host-side driver for the Cashu JavaCard applet

A PC/SC command-line tool that speaks the full command set in
[`spec/APDU.md`](../../spec/APDU.md), over either a contact or a contactless
reader.

Until this existed there was **no way to talk to a card at all** — the applet
had been exercised only under jCardSim, which cannot surface EEPROM exhaustion,
ECDH output framing differences, or a card whose `getS` returns short. Those are
precisely the bugs that only appear on silicon.

## Install

```bash
cd tools/cardctl
pip install -r requirements.txt
```

- **macOS** — PC/SC ships with the OS. Do **not** install `pcsc-lite`; it
  conflicts with the built-in daemon.

  ⚠️ **Do not use the system Python** (`/usr/bin/python3`, 3.9). `pip install
  pyscard` appears to succeed there, then fails at import with:

  ```
  ImportError: dynamic module does not define module export function (PyInit__scard)
  ```

  which looks like a broken reader or a bad install and is neither — it is an
  ABI mismatch in the native `_scard` module. Use a Homebrew Python instead:

  ```bash
  brew install python@3.13          # or any recent 3.x
  python3.13 -m venv .venv && source .venv/bin/activate
  pip install -r requirements.txt
  ```

  Verified working on Homebrew Python 3.14.
- **Debian/Ubuntu** — `sudo apt install pcscd libpcsclite-dev` and make sure
  `pcscd` is running.

## Quick start

```bash
python3 cardctl.py readers      # is the reader visible?
python3 cardctl.py selftest     # the one that matters
```

`selftest` is the card-arrival test. It selects the applet, reads the public
key, asks the card to sign random messages, and **verifies each signature
against BIP-340** — then checks that two signatures over the *same* message use
different nonces, which is a real security property rather than a nicety (a
nonce that is a pure function of `(d, msg)` lets a fault injector recover the
private key from two signatures).

```
PASS  SELECT applet  — version 0.1
PASS  GET_INFO  — v0.1, 32 slots, PIN unset
PASS  Schnorr capability advertised  — caps=0x03
PASS  GET_PUBKEY well-formed  — 02a1b2c3d4e5f60718…  (33 bytes)
PASS  SIGN_ARBITRARY + BIP-340 verify [1/3]
...
All 11 checks passed on physical hardware.
```

## Loading the applet

`cardctl` talks to an applet that is already installed. To install it, build the
CAP and use [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro):

```bash
cd applet && ant clean cap
gp -install target/cashu-javacard-0.1.0.cap
gp -list
```

**The card must be JavaCard 3.0.5 or later** — the applet needs
`KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY`, which does not exist in 3.0.4. JCOP4
works; JCOP3 / J3H145 / Feitian 3.0.4 cannot run this applet at all.

If loading over an ACR122U stalls part-way, suspect the interface before the
CAP: contactless loading is chattier and more fragile than contact. A contact
reader is the more reliable way to install, leaving NFC for tap testing.

## Commands

| Command | What it does |
|---|---|
| `readers` | list PC/SC readers |
| `selftest [--rounds N]` | full hardware check incl. BIP-340 verification |
| `info` | version, slot counts, capabilities, PIN state, balance |
| `pubkey` | 33-byte compressed public key |
| `balance` | sum of unspent proof amounts |
| `slots [--all]` | per-slot status |
| `proof <slot>` | decode one proof slot |
| `sign [--message HEX]` | SIGN_ARBITRARY, then verify |
| `spend <slot> [--message HEX]` | SPEND_PROOF, verify, confirm the slot flipped to spent |
| `load --keyset ID --amount N [--nonce HEX] [--c HEX] [--pin P]` | LOAD_PROOF. `ID` is the full 16-hex-char NUT-02 keyset id. |
| `clear-spent [--pin P]` | free spent slots |
| `verify-pin` / `set-pin` / `change-pin` | PIN management |
| `lock [--yes]` | **irreversibly** disable writes |
| `apdu <hex>` | send a raw APDU |

Global flags: `-r/--reader N` to pick a reader, `-v/--verbose` to log every APDU
to stderr — use `-v` when a command misbehaves, since the raw exchange usually
makes it obvious whether the card rejected the command or never saw it.

## A warning about `spend`

`SPEND_PROOF` is **irreversible**: the card marks the slot spent before it
returns the signature, and nothing can unmark it. On a card holding real
proofs, `spend` burns one. Use `sign` for signature testing — it exercises the
same signing path without consuming anything.

`load` without `--c` inserts a random placeholder in place of the mint's
signature. That is fine for exercising storage and slot management, but such a
proof can never be redeemed at a mint.

## Tests

```bash
python3 test_bip340.py    # verifier: spec vectors, reference round-trip, mutations
python3 test_apdu.py      # every command's bytes, against spec/APDU.md
```

Both run without a reader or a card. The BIP-340 tests matter more than they
look: `selftest`'s verdict is only as trustworthy as the verifier behind it, so
that verifier is checked against the specification's own vectors, round-tripped
against an independent reference signer, and mutation-tested to prove it can
say *no*.
