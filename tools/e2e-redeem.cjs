#!/usr/bin/env node
/*
 * e2e redeem: spend one card slot at the mint.
 *
 *   node tools/e2e-redeem.cjs <mint> <slot> <card-file>
 *
 * The merchant-terminal flow from docs/ARCHITECTURE.md, in one process: read a
 * slot, rebuild the NUT-10 P2PK secret, ask the card to sign the NUT-11 message,
 * attach the witness, and redeem at the mint. Redemption is a NUT-03 swap to
 * proofs relocked to the same card, so it proves the card's signature unlocked
 * the proof without needing a bolt11 (that would be a NUT-05 melt).
 *
 * The card is the only signer; this process never sees the private key.
 *
 * Env overrides: CLIENT_DIST (cashu-client build), CARDCTL, CARDCTL_PY.
 */
const path = require("path")
const fs = require("fs")
const { execFileSync } = require("child_process")

const REPO = path.resolve(__dirname, "..")
const CLIENT_DIST = process.env.CLIENT_DIST || path.resolve(REPO, "../cashu-client/dist")
const PY = process.env.CARDCTL_PY || path.resolve(REPO, "tools/cardctl/.venv/bin/python")
const CARDCTL = process.env.CARDCTL || path.resolve(REPO, "tools/cardctl/cardctl.py")

const cc = require(CLIENT_DIST)

const [, , MINT, SLOT_ARG, CARDFILE] = process.argv
const SLOT = Number(SLOT_ARG)

const die = m => { console.error(`FAIL: ${m}`); process.exit(1) }
const ensure = (v, what) => { if (v instanceof cc.CashuError) die(`${what}: ${v.message}`); return v }

async function main() {
  const file = cc.parseCardFile(fs.readFileSync(CARDFILE, "utf-8"))
  const slot = file.slots[SLOT] || die(`card file has no slot ${SLOT}`)
  console.log(`card pubkey : ${file.cardPubkey}`)
  console.log(`input slot  : ${SLOT} (${slot.amount} ${file.unit}, status ${slot.spent ? "spent" : "unspent"})`)

  const proof = cc.reconstructProofFromCard(slot, file.cardPubkey)
  const msg = cc.p2pkMessageToSign(proof)
  console.log(`P2PK message: ${msg.toString("hex")}`)

  const out = execFileSync(PY, [CARDCTL, "spend", String(SLOT), "--message", msg.toString("hex")], { encoding: "utf-8" })
  process.stdout.write(out.split("\n").map(l => "  card> " + l).join("\n") + "\n")
  const sig = out.match(/signature\s*:\s*([0-9a-f]{128})/)?.[1] || die("no signature parsed from cardctl")
  const signed = cc.attachP2PKWitness(proof, [sig])

  const keysets = ensure(await cc.getMintKeysets(MINT), "keysets")
  const ks = keysets.find(k => k.id === proof.id) || keysets.find(k => k.active && k.unit === file.unit) || die(`no keyset for ${proof.id}`)
  const ppk = ks.input_fee_ppk || 0
  const fee = cc.inputFee([proof], ppk)
  const outTotal = proof.amount - fee
  if (outTotal <= 0) die(`amount ${proof.amount} does not cover fee ${fee}`)
  const amounts = cc.splitIntoDenominations(outTotal)
  console.log(`redeem      : ${proof.amount} in − ${fee} fee = ${outTotal} out as [${amounts.join(", ")}] on keyset ${ks.id}`)

  const blindings = amounts.map(a => cc.createBlindedMessage(ks.id, a, file.cardPubkey))
  const outputs = blindings.map(b => ({ id: ks.id, amount: b.amount, B_: b.B_ }))
  const kd = ensure(await cc.getMintKeyset(MINT, ks.id), "keyset keys")

  const sigs = ensure(await cc.swapProofs(MINT, [signed], outputs, ppk), "swap")
  console.log(`swap        : OK — ${sigs.length} blind signature(s)`)

  const change = sigs.map((s, i) => {
    const C = cc.unblindSignature(s.C_, blindings[i].r, kd.keys[String(s.amount)])
    const dleq = s.dleq ? cc.proofDLEQFromBlindSignature(s.dleq, blindings[i].r) : undefined
    return { id: s.id, amount: s.amount, secret: blindings[i].secretStr, C, ...(dleq ? { dleq } : {}) }
  })
  console.log(`unblinded   : ${change.length} proof(s), ${change.reduce((t, p) => t + p.amount, 0)} ${file.unit}`)

  const states = await cc.checkProofStates(MINT, [proof])
  console.log(`mint says   : input is ${states instanceof cc.CashuError ? states.message : states[0].state}`)

  fs.writeFileSync("/tmp/change.json", cc.serializeCardFile({
    mint: MINT, unit: file.unit, cardPubkey: file.cardPubkey,
    slots: change.map((p, i) => ({ keysetId: p.id, amount: p.amount, nonce: blindings[i].nonce, C: p.C, spent: false })),
    note: "change from e2e redeem",
  }) + "\n")
  console.log(`wrote       : /tmp/change.json (${change.length} slot(s))`)
  console.log(`\nRESULT: slot ${SLOT} redeemed — the mint accepted the card's signature.`)
}

main().catch(e => die(e.stack || String(e)))
