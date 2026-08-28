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

Writers may add other top-level keys (`cardctl dump` emits a human-readable
`note`); readers ignore anything not listed here.

## Slot

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `keysetId` | string | yes | NUT-02 keyset id: 8 raw bytes, written as exactly 16 hex chars. Eight chars is half an id and a proof carrying it matches no keyset at the mint. |
| `amount` | integer | yes | Proof amount. The card's field is a 4-byte unsigned integer, so `0 < amount < 2^32`. |
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

`cardctl load-file` skips any slot with `"spent": true`.

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
- `tools/cardctl/testdata/card-file-v1.json` is a fixture produced by
  cashu-client's `serializeCardFile`, kept so the Python side is checked against
  bytes the TypeScript side actually wrote.
- cashu-client asserts the same tables from its own suite. That is what makes
  this a contract rather than a copied artifact: the fixture proves one file
  parsed once; the spec is what both sides are held to.
