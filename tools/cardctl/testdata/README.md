# cardctl test fixtures

## `card-file-v1.json`

A v1 card file. The body was produced by cashu-client's `serializeCardFile`
rather than hand-authored, so it cannot drift into agreement with a wrong
Python parser — that is the point of keeping it here.

The `spent` field was added by hand when the v1 schema gained it (see
`spec/CARD-FILE.md`), pending the mirror change in cashu-client. **Regenerate
this file from `serializeCardFile` once that lands**, so it goes back to being
entirely TypeScript-written output.

A fixture only ever proves that one file parsed once. The contract both
implementations are held to is `spec/CARD-FILE.md`, which
`test_card_file.py` parses and asserts the parser and writer against — that is
the check a rename fails.
