# Vision — why a Cashu bearer card exists

> **Read this first.** The rest of the documentation explains *how* the system
> works. This explains why it is shaped the way it is, and why several obvious
> alternatives were rejected. If you are about to propose a change that makes
> the card more like a debit card, the answer is probably here.

## The one-sentence version

**A physical card that holds Bitcoin-denominated ecash on its own chip, spends
it by tapping — with no phone, no account, and no internet at the point of sale
— and is worth exactly what it holds to whoever is holding it.**

## The problem this is for

Flash operates in the Caribbean. Three constraints shape everything:

**Connectivity is not a given.** A Lightning payment needs both parties online
at the moment of payment. In practice that fails at the checkout counter often
enough to matter — and a payment method that works *almost* always is a payment
method merchants stop reaching for.

**Not every user wants an account.** Onboarding a person into a custodial wallet
means KYC, a phone that can run the app, a phone number that survives, and a
recovery story they will not follow. For a tourist buying a coconut, or someone
paid in cash who wants to hold value in Bitcoin, that is an enormous amount of
ceremony for a small transaction.

**Custody is a liability.** Flash currently holds customer funds. That carries
regulatory weight, operational risk, and a permanent obligation — as this very
project demonstrated when the mint backing our ecash was found insolvent and had
to be re-funded. Every product that moves value *off* Flash's books and into the
user's own possession reduces that exposure.

A bearer card answers all three at once. It works offline because the value is
already on the card. It needs no account because it *is* the account. And it is
not custodial in the usual sense — Flash cannot spend what is on someone's card,
because Flash does not hold the key that authorises it.

## What "bearer" actually means here

This is the part people try to soften, so it is stated plainly:

**Whoever physically holds the card controls the funds on it.** There is no
cardholder name, no card number, no PIN on spending in the base profile, no
remote freeze, and no recovery. Lose the card and the money is gone, exactly as
if you had lost a banknote.

That is not an unfinished feature set. It is the product. The card is *cash*,
and cash has these properties. Every one of them is also a design constraint
that shows up later in the architecture — the applet is small because a bearer
instrument should be auditable; there is no personalisation because a card that
identifies you is not cash; the physical card carries the disclaimer in plain
language because users genuinely need to know.

If you want an instrument with recovery, freezing and an identity attached, that
already exists: it is the Flash app, backed by an account. This is the other
thing.

## What this replaces

**[FIP-04: Flash BTCPayServer Plugin](https://github.com/lnflash/fips) —
status: Implemented.** *(FIPs are internal to Flash; the repository is private.)*

The previous generation of Flash cards were **BoltCards**: NTAG 424 DNA tags
carrying an AES key, which authenticate a *server-side* balance over a
BTCPayServer plugin. That design works, and it shipped. It also has three
properties this project rejects:

| | BoltCard (FIP-04) | Cashu bearer card |
|---|---|---|
| Where the value lives | Server-side balance | **On the card's chip** |
| Works offline at POS | ✗ — the terminal must reach the server | **✓** |
| Custody | Flash holds the funds | **The holder does** |
| Cryptography on card | AES-128 CMAC (authentication) | **secp256k1 / BIP-340 (authorisation)** |

The BoltCard proves *who is tapping*. This card proves *that the value being
handed over is genuine* — which is a different and stronger claim, and the one
that makes offline payment possible at all. `btcpayserver-flash-plugin` is being
decommissioned (ENG-176).

## Why Cashu specifically

Cashu ecash gives three properties that together are unusual:

1. **Proofs are bearer tokens.** A Cashu proof is valid because it carries the
   mint's blind signature, not because a server says a balance exists. It can be
   verified by arithmetic, offline.
2. **It is small enough to fit.** A proof is 78 bytes in our on-card layout. A
   32-slot card holds a useful balance in ~2.5 KB of EEPROM — well within a
   JavaCard's budget.
3. **[NUT-11 P2PK](https://github.com/cashubtc/nuts/blob/main/11.md) locks a
   proof to a public key.** This is the load-bearing piece: proofs are locked to
   a key that exists only inside the card's secure element and is never
   exported. Copying the data off a card gets you proofs you cannot spend.

That third property is what makes a bearer *card* possible rather than merely a
bearer *token*. Without it, reading a card's memory would be equivalent to
stealing its balance.

## The honest trade: offline double-spend

The card marks a proof `SPENT` before it releases a signature, and nothing in
the APDU set can unmark it. That stops *the card* from spending the same proof
twice.

It does not — and cannot — stop someone who copied a proof's data from
redeeming it at the mint while the card still believes it is unspent. **An
offline merchant cannot detect this.** Only the mint knows what has been melted.

Every offline bearer instrument has this property; it is the reason physical
cash uses anti-counterfeiting rather than double-spend detection. The mitigations
are practical rather than cryptographic: the mint is the final authority and
rejects the second redemption, terminals settle promptly when they regain
connectivity, and cards hold small balances. Anyone claiming this design has
"zero double-spend risk" is wrong, and one of the documentation contributions to
this repo claimed exactly that.

## Where this sits in Flash

```
Flash app (custodial, online, KYC'd)     ← accounts, Lightning, USD, cash-out
        │
        │  top up a card
        ▼
Flash Card (bearer, offline-capable)     ← this project
        │
        │  tap to pay
        ▼
Merchant terminal → mint redemption      ← settles back into the Flash rails
```

The card is not a replacement for the app. It is the instrument for the
transactions the app is bad at: small, offline, anonymous, no-onboarding.

Related internal proposals for the surrounding context:
**FIP-05** (MonCash cross-border), **FIP-06** (phone-number Bitcoin sends) —
both are about reaching people the app cannot, which is the same motivation.

## Status: this is R&D

Be clear-eyed about maturity. As of this writing:

- The applet **builds and its crypto is correct in simulation** — but has never
  run on a physical card. Two bugs found in review (a modular-reduction carry
  error and an EEPROM leak) were both invisible to the simulator and would each
  have been fatal in the field.
- There is **no merchant terminal software**. `flash-pos` contains no Cashu code.
  Any document describing an end-to-end tap-to-pay flow is describing intent.
- The `cardctl` tool can drive a card over PC/SC once one exists.
- `cashu-client` can now load *and* redeem, which it could not before.

The first real signature off a JavaCard 3.0.5 chip is the milestone that turns
this from a design into a product. It has not happened yet.

## What would make this project fail

Worth naming, so contributors can push back early:

1. **Nobody builds the terminal.** Without a merchant-side reader, this is a
   card that can be loaded and never spent in the real world.
2. **The bearer model gets softened into a debit card.** Adding names, freezes
   and recovery re-introduces custody and the reason to exist evaporates.
3. **The mint stays fragile.** A bearer card is only as good as the mint that
   honours its proofs. See [`docs/SECURITY-MODEL.md`](SECURITY-MODEL.md).
4. **Hardware reality bites.** Chip position, EEPROM budget, module supply and
   card cost are all still unproven at volume.

---

**Next:** [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the pieces fit together,
or [`DECISIONS.md`](DECISIONS.md) for the specific calls and their reasoning.
