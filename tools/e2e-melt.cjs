#!/usr/bin/env node
/*
 * e2e melt: pay a Lightning invoice by melting a card slot (NUT-05).
 *
 *   node tools/e2e-melt.cjs <mint> <slot> <card-file> [--invoice <bolt11>]
 *
 * With no --invoice, the script melts the card proof to pay a fresh mint quote
 * at the same mint — a self-referential but entirely real Lightning payment:
 * the mint's node settles the invoice, the quote flips PAID, and the value can
 * be minted back out. That makes the run autonomous AND verifiable end to end:
 * card -> Lightning -> card, minus the routing fee.
 *
 * The melt is not idempotent and the card burns its slot on SPEND_PROOF before
 * the mint sees anything, so the script refuses to submit a set the mint would
 * reject (meltAmountRequired check) and reports the recovery path on failure:
 * the proof itself is still unspent at the mint and re-signable via
 * SIGN_ARBITRARY, which does not consume a slot.
 */
const path = require("path")
const fs = require("fs")
const { execFileSync } = require("child_process")

const REPO = path.resolve(__dirname, "..")
const CLIENT_DIST = process.env.CLIENT_DIST || path.resolve(REPO, "../cashu-client/dist")
const PY = process.env.CARDCTL_PY || path.resolve(REPO, "tools/cardctl/.venv/bin/python")
const CARDCTL = process.env.CARDCTL || path.resolve(REPO, "tools/cardctl/cardctl.py")
const sleep = ms => new Promise(r => setTimeout(r, ms))

const cc = require(CLIENT_DIST)

const [, , MINT, SLOT_ARG, CARDFILE, , INVOICE] = process.argv
const SLOT = Number(SLOT_ARG)

const die = m => { console.error(`FAIL: ${m}`); process.exit(1) }
const ensure = (v, what) => { if (v instanceof cc.CashuError) die(`${what}: ${v.message}`); return v }

// Unblind a blind signature back into a spendable proof, carrying the nonce so
// the result can be written straight into a card file.
const unblind = (sig, bd, keys) => ({
  id: sig.id,
  amount: sig.amount,
  secret: bd.secretStr,
  C: cc.unblindSignature(sig.C_, bd.r, keys[String(sig.amount)]),
  nonce: bd.nonce,
  ...(sig.dleq ? { dleq: cc.proofDLEQFromBlindSignature(sig.dleq, bd.r) } : {}),
})

async function main() {
  const file = cc.parseCardFile(fs.readFileSync(CARDFILE, "utf-8"))
  const slot = file.slots[SLOT] || die(`card file has no slot ${SLOT}`)
  if (slot.spent) die(`slot ${SLOT} is already spent on the card`)
  console.log(`card pubkey : ${file.cardPubkey}`)
  console.log(`input slot  : ${SLOT} (${slot.amount} ${file.unit})`)

  const proof = cc.reconstructProofFromCard(slot, file.cardPubkey)
  const keysets = ensure(await cc.getMintKeysets(MINT), "keysets")
  const ks = keysets.find(k => k.id === proof.id) || keysets.find(k => k.active && k.unit === file.unit) || die(`no keyset for ${proof.id}`)
  const ppk = ks.input_fee_ppk || 0
  const kd = ensure(await cc.getMintKeyset(MINT, ks.id), "keyset keys")

  // Pick the largest invoice the card proof can actually cover: invoice +
  // fee reserve + input fee must fit inside the proof, or the melt is a
  // guaranteed reject that burns the slot for nothing.
  let mintQuote, meltQuote
  for (const candidate of [proof.amount, 12, 8, 4]) {
    if (candidate > proof.amount) continue
    mintQuote = ensure(await cc.requestMintQuote(MINT, candidate, file.unit), "mint quote")
    meltQuote = ensure(await cc.requestMeltQuote(MINT, INVOICE || mintQuote.paymentRequest, file.unit), "melt quote")
    const need = cc.meltAmountRequired(meltQuote, [proof], ppk)
    console.log(`quotes      : invoice ${candidate} ${file.unit} + reserve ${meltQuote.feeReserve} = needs ${need} of ${proof.amount}`)
    if (need <= proof.amount) break
    mintQuote = meltQuote = undefined
    await sleep(1500)
  }
  if (!meltQuote) die(`no invoice amount fits inside a ${proof.amount} ${file.unit} proof`)
  const needed = cc.meltAmountRequired(meltQuote, [proof], ppk)

  const msg = cc.p2pkMessageToSign(proof)
  console.log(`P2PK message: ${msg.toString("hex")}`)
  const out = execFileSync(PY, [CARDCTL, "spend", String(SLOT), "--message", msg.toString("hex")], { encoding: "utf-8" })
  process.stdout.write(out.split("\n").map(l => "  card> " + l).join("\n") + "\n")
  const sig = out.match(/signature\s*:\s*([0-9a-f]{128})/)?.[1] || die("no signature parsed from cardctl")
  const signed = cc.attachP2PKWitness(proof, [sig])

  // Anything above what the mint may keep comes back as change — supply
  // blinded outputs for it or the mint pockets the difference.
  const remainder = proof.amount - needed
  const changeAmounts = remainder > 0 ? cc.splitIntoDenominations(remainder) : []
  const changeBlindings = changeAmounts.map(a => cc.createBlindedMessage(ks.id, a, file.cardPubkey))
  console.log(`melt        : quote ${meltQuote.quoteId} — ${proof.amount} in, ${remainder} back as change [${changeAmounts.join(", ") || "none"}]`)

  const result = ensure(await cc.meltProofs(MINT, meltQuote.quoteId, [signed],
    changeBlindings.length ? changeBlindings.map(b => ({ id: ks.id, amount: b.amount, B_: b.B_ })) : undefined),
  "melt")
  console.log(`melt state  : ${result.state}${result.paymentPreimage ? ` (preimage ${result.paymentPreimage.slice(0, 16)}…)` : ""}`)
  if (result.state !== "PAID") die(`melt did not settle: ${result.state}`)

  // The invoice the melt just paid was a mint quote — mint the paid value out.
  let minted = [], mintedBlindings = []
  for (let i = 0; i < 8; i++) {
    const st = await cc.getMintQuoteState(MINT, mintQuote.quoteId)
    if (st instanceof cc.CashuError) { await sleep(3000); continue }
    if (st.state === "PAID" || st.state === "ISSUED") {
      const amounts = cc.splitIntoDenominations(meltQuote.amount)
      mintedBlindings = amounts.map(a => cc.createBlindedMessage(ks.id, a, file.cardPubkey))
      const sigs = ensure(await cc.mintProofs(MINT, mintQuote.quoteId,
        mintedBlindings.map(b => ({ id: ks.id, amount: b.amount, B_: b.B_ }))), "mint")
      minted = sigs.map((s, i) => unblind(s, mintedBlindings[i], kd.keys))
      break
    }
    await sleep(3000)
  }
  if (!minted.length) die(`mint quote ${mintQuote.quoteId} never flipped PAID after the melt settled`)

  const changeProofs = (result.change || []).map((s, i) => unblind(s, changeBlindings[i], kd.keys))
  const recovered = [...minted, ...changeProofs]
  const total = recovered.reduce((t, p) => t + p.amount, 0)
  console.log(`recovered   : ${minted.length} minted + ${changeProofs.length} change = ${total} ${file.unit}` +
    ` (net Lightning cost ${proof.amount - total})`)

  const outFile = "/tmp/melt-recovered.json"
  fs.writeFileSync(outFile, cc.serializeCardFile({
    mint: MINT, unit: file.unit, cardPubkey: file.cardPubkey,
    slots: recovered.map(p => ({ keysetId: p.id, amount: p.amount, nonce: p.nonce, C: p.C, spent: false })),
    note: "recovered from NUT-05 melt",
  }) + "\n")
  console.log(`wrote       : ${outFile}`)
  console.log(`\nRESULT: NUT-05 melt settled on silicon — the mint paid a Lightning invoice with the card's proof.`)
}

main().catch(e => die(e.stack || String(e)))
