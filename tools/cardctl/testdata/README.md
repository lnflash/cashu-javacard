# cardctl test fixtures

## `card-file-v1.json`

A v1 card file, regenerated through the `lnflash/cashu-client#5` toolchain and
verified **accepted by that branch's `parseCardFile`** — parseCardFile-accepts,
not serializeCardFile-wrote: `serializeCardFile` refuses `spent: true` by
design (that direction ends at LOAD_PROOF, which has no spent bit), so no
serializer on either side can emit a full dump with a spent slot. Full dumps
with spent slots are `cardctl dump`'s side of the format.

Keeping the fixture TypeScript-verified is the point of keeping it here: it
cannot drift into agreement with a wrong Python parser. Note that agreement is
with the #5 branch, not `main` — until #5 lands, `main`'s `parseCardFile`
still rejects `spent`, which is why the two PRs must merge together (see the
status note in `spec/CARD-FILE.md`).

A fixture only ever proves that one file parsed once. The contract both
implementations are held to is `spec/CARD-FILE.md`, which
`test_card_file.py` parses and asserts the parser and writer against — that is
the check a rename fails. Note that only the Python side reads that document
today; making cashu-client assert the same tables is the other half of the job.
