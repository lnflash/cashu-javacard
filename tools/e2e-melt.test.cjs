// node --test tools/e2e-melt.test.cjs
//
// Argument handling for e2e-melt.cjs. The script itself needs a card and a
// cashu-client build; this only loads parseArgs/recoveredPath, which is why
// the client is required lazily inside main().
const test = require("node:test")
const assert = require("node:assert/strict")
const { parseArgs, recoveredPath } = require("./e2e-melt.cjs")

test("positional args without --invoice select the self-quote path", () => {
  assert.deepEqual(parseArgs(["https://mint", "0", "card.json"]),
    { mint: "https://mint", slot: 0, cardFile: "card.json", invoice: undefined })
})

test("--invoice <bolt11> is read only behind its flag", () => {
  assert.equal(parseArgs(["https://mint", "2", "card.json", "--invoice", "lnbc1abc"]).invoice, "lnbc1abc")
})

test("a bare bolt11 is refused rather than silently ignored", () => {
  assert.throws(() => parseArgs(["https://mint", "0", "card.json", "lnbc1abc"]), /unknown argument "lnbc1abc"/)
})

test("an unknown flag is refused rather than skipped over", () => {
  assert.throws(() => parseArgs(["https://mint", "0", "card.json", "--bogus", "lnbc1abc"]), /unknown argument "--bogus"/)
})

test("--invoice without a value is an error", () => {
  assert.throws(() => parseArgs(["https://mint", "0", "card.json", "--invoice"]), /requires a bolt11/)
})

test("missing positionals and bad slots are errors", () => {
  assert.throws(() => parseArgs(["https://mint", "0"]), /usage/)
  assert.throws(() => parseArgs(["https://mint", "x", "card.json"]), /slot must be/)
})

test("recovered proofs go to a per-quote path beside the card file", () => {
  assert.equal(recoveredPath("/cards/card.json", "abc-123"), "/cards/card.melt-abc-123.json")
  assert.equal(recoveredPath("card", "q/../x"), "card.melt-q____x.json")
  assert.notEqual(recoveredPath("card.json", "q1"), recoveredPath("card.json", "q2"))
})
