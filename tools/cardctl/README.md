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
| `load-file PATH [--pin P]` | LOAD_PROOF every proof in a card file. Refuses if the file is for a different card, or if the card has too few free slots. Re-runnable: proofs already on the card are skipped, spent ones are never written back. |
| `dump --mint URL [--unit U] [--out PATH] [--force] [--unspent-only]` | Write the card's slots out as a card file. `--out` refuses to overwrite without `--force`. |
| `clear-spent [--pin P]` | free spent slots |
| `verify-pin` / `set-pin` / `change-pin` | PIN management |
| `lock [--yes]` | **irreversibly** disable writes |
| `apdu <hex>` | send a raw APDU |

Breaking changes to `load` (if you have a provisioning script written against an
earlier revision, all three fail loudly rather than silently):

- `--secret` was renamed `--nonce`. The value is unchanged — the card stores
  32 bytes of P2PK *nonce*, and a reader rebuilds the full NUT-10 secret from
  the nonce plus `GET_PUBKEY`.
- `--keyset-hex` was removed. Hex is now the only interpretation of `--keyset`,
  so the flag had no meaning left; pass the full 16-hex-char id to `--keyset`.
- `Card.get_proof()` returns that field under the key `nonce`, not `secret`.

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

## Card files

`dump` and `load-file` speak the interchange format in
[`spec/CARD-FILE.md`](../../spec/CARD-FILE.md), the intended contract with
cashu-client's `serializeCardFile` / `parseCardFile`. `test_card_file.py` parses
the spec and asserts this driver's parser and writer against the published field
tables, so a rename on this side fails in CI rather than at a card reader.

> **The two halves do not interoperate yet.** cashu-client (`lnflash/cashu-client#5`)
> does not know the `spent` field and rejects any key outside its allowlist, so
> today it refuses what `dump` writes and `load-file` refuses what it writes.
> The spec's status note has the details; the two changes must merge together.

Four things the format insists on, all because a card file is bearer money:

- **`spent` is required, not defaulted.** A file that omits it is not a file of
  unspent proofs, it is a file whose state is unknown — and guessing "unspent"
  turns settled money back into spendable balance on the next `load-file`.
- **Unknown fields are refused, not ignored.** At document and slot level. An
  unrecognised key means the writer added something without bumping `version`;
  dropping it silently is how the two sides drift apart in the first place.
- **Amounts are positive powers of two below 2^32,** and keyset ids are NUT-02
  v0 (`00` version byte). Both are enforced by `load` and `load-file` alike, so
  the tool cannot put a proof on a card that the file format then refuses to
  carry back off it.
- **`load-file` is re-runnable.** `LOAD_PROOF` commits one proof at a time with
  no transaction around the file, so a failure part-way through leaves half of
  it on the card. Re-running skips whatever is already there by nonce instead of
  writing duplicates, and everything checkable — capacity, amounts, points — is
  checked before the first write. A nonce the card has already *spent* is
  reported as spent, not as "already loaded".

`dump` validates the document it assembled before writing it, so a mistake like
`dump --mint "$UNSET_VAR"` fails loudly instead of leaving an unloadable backup.

## Tests

```bash
python3 test_bip340.py            # verifier: spec vectors, reference round-trip, mutations
python3 test_apdu.py              # every command's bytes, against spec/APDU.md
python3 test_spec_consistency.py  # cardctl vs spec/APDU.md, parsed from the doc
python3 test_card_file.py         # card file read/write, against spec/CARD-FILE.md
```

All four run without a reader or a card. The BIP-340 tests matter more than they
look: `selftest`'s verdict is only as trustworthy as the verifier behind it, so
that verifier is checked against the specification's own vectors, round-tripped
against an independent reference signer, and mutation-tested to prove it can
say *no*.
