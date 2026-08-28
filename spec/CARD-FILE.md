# Card File — interchange format v1

The mint protocol lives in TypeScript (`lnflash/cashu-client`) and the host-side
driver is Python (`tools/cardctl`). Proofs cross that boundary as a JSON file:
`cardctl dump` writes one off a card, `cardctl load-file` writes one onto a card,
and `serializeCardFile` / `parseCardFile` in cashu-client do the same on the
other side.

This document is the contract. It exists for the same reason `APDU.md` does:
this repo's characteristic bug is not a crash, it is a document and an
implementation drifting apart while both look fine on their own. A file that two
implementations disagree about is bearer money nobody can spend, so the field
names below are asserted against the parser on every push
(`tools/cardctl/test_card_file.py`) rather than trusted.

The vocabulary is the **card's**, not the mint's: `nonce`, not `secret`, and a
16-hex-character `keysetId`. A file that says `secret` was written against a
wrong model — a NUT-10 P2PK secret is ~150 bytes of JSON and cannot live in a
32-byte slot field.

> **Status: v1 is not final until both halves ship it.**
> `spent` (below) exists on the Python side only. `lnflash/cashu-client#5` — the
> other half of v1 — does not know the field: its `SLOT_FIELDS` allowlist is
> `keysetId, amount, nonce, C`, and its parser rejects any key outside it. Until
> that PR adds `spent` to `SLOT_FIELDS`, `CardProofSlot`, `parseCardSlot` and
> `serializeCardFile`, every file `cardctl dump` writes is refused by
> `parseCardFile` and every file `serializeCardFile` writes is refused by
> `cardctl load-file`. **Neither PR may merge alone.** The paired change, and a
> regenerated `tools/cardctl/testdata/card-file-v1.json`, land together or v1
> ships without `spent` on both sides and gains it as v2.
>
> One more thing owed on that side: `requireAmount` accepts any power of two up
> to `Number.MAX_SAFE_INTEGER`. The card's field is four bytes wide, so the
> bound below (`amount < 2^32`) is the real one and cashu-client must adopt it —
> otherwise the TypeScript half writes files the card physically cannot hold.

---

## Document

```json
{
  "version": 1,
  "mint": "https://forge.flashapp.me",
  "unit": "sat",
  "cardPubkey": "032994631ef9a4ba5b0db2f44b4d0d8a4b0eec49bed16091c23c171a8c553a03da",
  "slots": [
    {
      "keysetId": "0059534ce0bfa19a",
      "amount": 8,
      "nonce": "abababababababababababababababababababababababababababababababab",
      "C": "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
      "spent": false
    }
  ]
}
```

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `version` | integer | yes | Schema version. Must be exactly `1`; a reader that does not recognise the value refuses the file rather than guessing. |
| `mint` | string | yes | Mint URL these proofs belong to. Non-empty. |
| `unit` | string | yes | Keyset unit, e.g. `sat`. Non-empty. |
| `cardPubkey` | string | yes | The card's 33-byte compressed secp256k1 public key, 66 hex chars, `02`/`03` prefix. Proofs are P2PK-locked to this key. |
| `slots` | array | yes | Zero or more slot objects, in card slot order. |
| `note` | string | no | Free-form provenance for a human. Never trusted, never acted on. `cardctl dump` emits one; a reader must tolerate its absence. |

**Readers reject any key not listed above, at document *and* slot level.** There
is no ignore-and-continue: silently dropping an unrecognised field is exactly
the drift this format exists to prevent — a writer adds a field, forgets to bump
`version`, and the other side discards it without a word. The failure then
surfaces at the mint, or as money that quietly went nowhere. `version` is the
mechanism for adding a field; an allowlist is what forces its use.

`note` is the one optional key, and it is on the list. Anything else — including
a field a future revision genuinely needs — is a hard boundary failure until it
appears here with a version bump.

## Slot

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `keysetId` | string | yes | NUT-02 **v0** keyset id: 8 raw bytes, written as exactly 16 hex chars, first byte `00`. Eight chars is half an id and a proof carrying it matches no keyset at the mint; a non-`00` version byte is not a v0 id and is refused rather than guessed at. |
| `amount` | integer | yes | Proof amount: a **positive power of two**, and `0 < amount < 2^32`. A mint keyset has no key for amount 3, so a non-power-of-two proof is rejected on redemption — after the slot is burned. The upper bound is the card's field width: `LOAD_PROOF` carries the amount as a 4-byte unsigned integer. |
| `nonce` | string | yes | The 32-byte P2PK nonce, 64 hex chars. **Not** the NUT-10 secret string — a reader rebuilds that from the nonce plus `cardPubkey`. |
| `C` | string | yes | The mint's 33-byte compressed signature point, 66 hex chars, `02`/`03` prefix. |
| `spent` | boolean | yes | Whether the card has already marked this slot spent. |

Hex is case-insensitive on read and lower-case on write. `0x` prefixes are
tolerated on read and never written.

### Why `spent` is required and not defaulted

A spent slot is still *owed* until it settles at the mint, so a dump keeps it —
dropping it loses money. But the redeemer has to be able to tell the two kinds
apart, and a card cannot: `LOAD_PROOF` has no spent bit, so a spent proof
written back onto a card comes back as unspent and inflates the balance with
money that is already gone.

Defaulting a missing `spent` to `false` reintroduces exactly that. A file
written by an implementation that does not know about the field is not a file
whose proofs are all unspent — it is a file whose state is unknown, and the
right response is to refuse it. Hence: required, no default.

`cardctl load-file` skips any slot with `"spent": true`. It also refuses to call
a slot "already loaded" when the card has already burned that nonce: a stale
file reloaded against a card that spent one of its proofs reports
`already SPENT on this card` and counts it separately, rather than telling the
operator money that is gone is safely present.

## Version semantics

`version` is a single integer, bumped whenever a field is added, removed,
renamed, or has its meaning changed. There is no minor version and no
forward-compatibility window: a reader accepts the versions it knows and
refuses the rest by number.

Additive-looking changes still require a bump, because "field absent" and
"field present and false" are different claims about money — see above.

## Cross-implementation checks

- `tools/cardctl/test_card_file.py` parses the two tables above and asserts that
  the names `cardctl`'s parser requires, and the names its writer emits, are
  exactly the names published here. A rename on the Python side fails in CI.
- `tools/cardctl/testdata/card-file-v1.json` is a fixture whose body was produced
  by cashu-client's `serializeCardFile`, kept so the Python side is checked
  against bytes the TypeScript side actually wrote. Its `spent` fields were
  added by hand, because `serializeCardFile` does not emit them yet — see the
  status note at the top. Regenerating it from an updated `serializeCardFile` is
  part of the paired change, not optional cleanup.
- **Not yet true, and required before v1 ships:** cashu-client asserting these
  same tables from its own suite. Today it holds its own copies of the field
  lists and does not read this document, so the "contract" is enforced on the
  Python side only. Until that lands, the fixture proves one file parsed once
  and nothing more.

## Writers validate too

`cardctl dump` runs the document it assembled through the same validator
`cardctl load-file` uses before writing a byte, and cashu-client's
`serializeCardFile` round-trips through `parseCardFile`. A writer that emits
what its own reader refuses turns one schema into two behaviours — and the file
it produced is the card's only off-card record, so the discrepancy is found
long after the card has moved on.
