# cardctl test fixtures

## `card-file-v1.json`

A v1 card file. The body was produced by cashu-client's `serializeCardFile`
rather than hand-authored, so it cannot drift into agreement with a wrong
Python parser — that is the point of keeping it here.

The `spent` field was added by hand when the v1 schema gained it (see
`spec/CARD-FILE.md`), because cashu-client does not emit it yet. That is not a
cosmetic gap: `lnflash/cashu-client#5` rejects any slot key outside
`keysetId, amount, nonce, C`, so the two halves currently refuse each other's
files in both directions. **Regenerate this file from `serializeCardFile` as
part of the paired change that adds `spent` on the TypeScript side** — the two
must merge together, and this fixture goes back to being entirely
TypeScript-written output when they do.

A fixture only ever proves that one file parsed once. The contract both
implementations are held to is `spec/CARD-FILE.md`, which
`test_card_file.py` parses and asserts the parser and writer against — that is
the check a rename fails. Note that only the Python side reads that document
today; making cashu-client assert the same tables is the other half of the job.
