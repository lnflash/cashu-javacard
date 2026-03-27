# User Guide — Cashu JavaCard

> Turn any NFC JavaCard into a physical Cashu wallet. Tap to pay, tap to receive — no internet required at point of sale.

---

## What is cashu-javacard?

**cashu-javacard** is an applet that runs on NFC-enabled JavaCard chips. It stores [Cashu ecash](https://cashu.space) proofs directly on a physical card, enabling offline point-of-sale payments using NFC tap — similar to a prepaid debit card, but with the privacy and decentralization of Bitcoin.

### How it works in one sentence

You load Cashu proofs onto the card over NFC (online), then spend them by tapping the card at a merchant terminal (offline) — the merchant redeems the proofs later when connected.

### Why use a physical card?

- **Offline payments** — works without internet at the point of sale
- **Privacy** — bearer instrument, no account or identity required
- **Hardware security** — private key never leaves the chip
- **Simplicity** — tap and go, no phone or app needed at checkout

---

## Supported Cards

Before purchasing a card, check compatibility:

| Card | Status | Price | Notes |
|------|--------|-------|-------|
| **Feitian JavaCard 3.0.4** | ✅ Supported | ~$2/card | Best for development and testing |
| **NXP JCOP4 SmartMX3 (P71)** | ✅ Supported | ~$5/card | CC EAL 5+ certified; production-grade |
| NXP NTAG 424 DNA | ❌ Not supported | — | Insufficient memory, no EC crypto |
| Generic JavaCard 3.0.1+ | ⚠️ May work | Varies | Verify `ALG_EC_SVDP_DH_PLAIN_XY` support |
| JavaCard 2.2.x | ❌ Not supported | — | Missing required APIs |

### Where to buy

- **Feitian JavaCard 3.0.4**: Available from [Feitian](https://www.ftsafe.com/) or resellers on AliExpress. Search for "Feitian JavaCard NFC".
- **NXP JCOP4 SmartMX3**: Contact NXP or authorized distributors. Higher security certification for production use.

> **Tip for beginners**: Start with Feitian cards — they're cheap, widely available, and work perfectly for testing.

---

## Quick Start

### What you need

1. A compatible JavaCard (see above)
2. An NFC card reader (USB, ~$15)
3. A machine with JDK 11+ and [GlobalPlatformPro](#install-globalplatformpro)
4. The `.cap` applet file (built from source or downloaded from releases)

### Install GlobalPlatformPro

GlobalPlatformPro (`gp`) is the standard tool for managing JavaCard applets.

```bash
# Download
curl -L https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar \
     -o /usr/local/bin/gp.jar

# Create wrapper
cat > /usr/local/bin/gp << 'EOF'
#!/bin/sh
exec java -jar /usr/local/bin/gp.jar "$@"
EOF
chmod +x /usr/local/bin/gp
```

### Load the applet onto your card

```bash
# 1. Insert card into NFC reader
# 2. Verify the card is detected
gp --list
# You should see: ISD: A000000151000000 (OP_READY)

# 3. Install the applet
gp --install target/cashu-javacard-0.1.0.cap

# 4. Verify installation
gp --list
# You should see: APP: D276000085010201 (SELECTABLE)
```

### Verify your card is working

```bash
# Select the applet
gp --apdu 00A4040007D2760000850102
# Response: 0000 9000 ✅

# Check card info
gp --apdu B0010000
# Response: version + slot stats + SW 9000 ✅

# Get card's public key
gp --apdu B0100000
# Response: 33-byte compressed secp256k1 pubkey + SW 9000 ✅
```

Your card is now ready to receive Cashu proofs!

---

## Loading Money onto Your Card (Top-Up)

Top-up happens **online** — you need internet access and a connection to a Cashu mint (e.g., [forge.flashapp.me](https://forge.flashapp.me)).

### How top-up works

```
┌──────────────────────────────────────────────────────┐
│                    TOP-UP (Online)                    │
│                                                      │
│  flash-mobile / flash-pos                            │
│         │                                            │
│         ▼                                            │
│  Flash backend (issues request to mint)              │
│         │                                            │
│         ▼                                            │
│  forge.flashapp.me (Cashu mint)                      │
│         │                                            │
│         ▼  Cashu proofs locked to card pubkey        │
│  [NFC write to JavaCard via LOAD_PROOF]              │
└──────────────────────────────────────────────────────┘
```

### Step by step

1. **Open your wallet app** (e.g., [flash-mobile](https://github.com/lnflash/flash-mobile) or [flash-pos](https://github.com/lnflash/flash-pos))
2. **Tap your card** to read its public key
3. **Enter the amount** you want to load
4. **Confirm the transaction** — the app contacts the Cashu mint
5. **The mint generates proofs** locked to your card's public key (P2PK)
6. **Proofs are written to the card** via NFC (`LOAD_PROOF` command)
7. **Done!** Your card now holds the balance

> **Security note**: Proofs are bound to your card's public key. Even if someone intercepts the NFC communication, they cannot spend the proofs without the physical card (the private key never leaves the chip).

---

## Paying with Your Card (NFC Tap)

Payment happens **offline** — no internet required at the point of sale.

### How payment works

```
┌──────────────────────────────────────────────────────┐
│                   PAYMENT (Offline)                   │
│                                                      │
│  Customer taps card at merchant terminal             │
│         │                                            │
│         ▼                                            │
│  flash-pos reads proof from card (no internet)       │
│         │                                            │
│         ▼                                            │
│  Card: SPEND_PROOF marks proof as spent              │
│       + returns NUT-11 P2PK Schnorr signature        │
│         │                                            │
│         ▼                                            │
│  Merchant verifies mint signature locally            │
│         │                                            │
│         ▼                                            │
│  Later (online): merchant redeems proofs at mint     │
└──────────────────────────────────────────────────────┘
```

### Step by step

1. **Merchant opens their POS app** (e.g., [flash-pos](https://github.com/lnflash/flash-pos))
2. **Customer taps their card** on the NFC reader
3. **POS reads the available balance** from the card (`GET_BALANCE`)
4. **Customer confirms the amount** (or enters a partial amount)
5. **Card marks the proof as spent** atomically (`SPEND_PROOF`)
   - This is **irreversible** — once spent, the proof cannot be unspent
   - The card returns a Schnorr signature authorizing the spend
6. **POS receives the proof + signature** and queues it for redemption
7. **Later, when online**, the POS redeems the proofs at the Cashu mint

> **Key insight**: The merchant takes on zero double-spend risk. The card's hardware enforces single-spend — once a proof is marked spent, it stays spent. The merchant only needs internet eventually (not immediately) to redeem the proofs.

---

## Payment Flow Diagram

```
                         ┌─────────────┐
                         │  Cashu Mint  │
                         │ forge.flash  │
                         └──────┬──────┘
                                │
                    ┌───────────┼───────────┐
                    │     Online flow        │
                    ▼                        ▼
           ┌──────────────┐        ┌──────────────┐
           │ flash-mobile │        │  flash-pos   │
           │  (customer)  │        │  (merchant)  │
           └──────┬───────┘        └──────┬───────┘
                  │                       │
                  │    NFC Top-Up         │
                  │  (LOAD_PROOF)         │
                  ▼                       │
           ┌──────────────┐               │
           │  JavaCard    │               │
           │  (physical)  │               │
           └──────┬───────┘               │
                  │                       │
                  │    NFC Payment         │
                  │  (SPEND_PROOF)         │
                  └──────────────────────►│
                                          │
                                    ┌─────▼─────┐
                                    │ Proof +   │
                                    │ Signature │
                                    └─────┬─────┘
                                          │
                                          │  Online redemption
                                          ▼
                                   ┌──────────────┐
                                   │  Cashu Mint  │
                                   │  (redeems)   │
                                   └──────────────┘
```

---

## Available Commands (APDU Reference)

For developers and integrators. All commands use `CLA = B0` unless noted.

### Read commands (no authentication)

| INS | Command | Description |
|-----|---------|-------------|
| `0x01` | `GET_INFO` | Applet version, slot stats, capabilities |
| `0x10` | `GET_PUBKEY` | Card's secp256k1 public key (33 bytes) |
| `0x11` | `GET_BALANCE` | Sum of unspent proof amounts |
| `0x12` | `GET_PROOF_COUNT` | Number of non-empty slots |
| `0x13` | `GET_PROOF` | Full proof data at slot index |
| `0x14` | `GET_SLOT_STATUS` | Bulk status of all 32 slots |

### Spend commands (no PIN — bearer semantics)

| INS | Command | Description |
|-----|---------|-------------|
| `0x20` | `SPEND_PROOF` | Mark proof spent + return Schnorr signature |
| `0x21` | `SIGN_ARBITRARY` | Sign 32-byte message (for auth challenges) |

### Write commands (PIN required if set)

| INS | Command | Description |
|-----|---------|-------------|
| `0x30` | `LOAD_PROOF` | Store a new proof on the card |
| `0x31` | `CLEAR_SPENT` | Garbage-collect spent proof slots |

### Authentication

| INS | Command | Description |
|-----|---------|-------------|
| `0x40` | `VERIFY_PIN` | Verify provisioning PIN |
| `0x41` | `SET_PIN` | Set PIN (one-time, during personalization) |
| `0x42` | `CHANGE_PIN` | Change existing PIN |

> Full command reference with byte-level details: [spec/APDU.md](../spec/APDU.md)

---

## Security Model

### What the card protects

- **Private key** — generated on-chip at install time; never exported
- **Spend protection** — `SPEND_PROOF` is atomic and irreversible (hardware-enforced)
- **Proof integrity** — proofs are verified against mint signatures before acceptance

### What the card does NOT protect

- **Physical theft** — the card is a bearer instrument. Whoever holds it can spend it (unless PIN is enabled via Profile B+)
- **Denial of service** — an attacker with physical access can damage the card
- **Amount privacy** — the balance command (`GET_BALANCE`) is unauthenticated by default

### Optional PIN protection (Profile B+)

If you enable PIN protection:

- `LOAD_PROOF` and `CLEAR_SPENT` require PIN verification
- PIN is 4–8 bytes, set once during personalization
- Wrong PIN decrements a retry counter; after max retries, the card is locked
- PIN session is transient — cleared when the NFC session ends

---

## Frequently Asked Questions

### Do I need a phone to pay?

No. The card works standalone — just tap it at any compatible POS terminal. You only need a phone (or computer) to top up the card.

### Can I check my balance without a POS terminal?

Yes. Any NFC reader that can send APDUs can query `GET_BALANCE`. Some phones with NFC can do this with a simple app.

### What happens if I lose my card?

The card is a bearer instrument — whoever finds it can spend the balance. There is no recovery mechanism. Treat it like cash.

### Can I reuse spent slots?

Yes. After spending, call `CLEAR_SPENT` (requires PIN) to free up slots. Freed slots can receive new proofs via `LOAD_PROOF`.

### How many transactions can the card hold?

Up to 32 proofs (configurable at install time). Each proof can be any denomination. Use `CLEAR_SPENT` periodically to reclaim slots.

### Does the merchant need internet?

Not immediately. The merchant can accept payments offline and redeem proofs later when connected. This is the core use case — offline point-of-sale.

### Which Cashu mints are supported?

Any Cashu mint implementing NUT-00 through NUT-11. The reference mint is [forge.flashapp.me](https://forge.flashapp.me) running Nutshell 0.18.0.

---

## Related Projects

| Project | Description |
|---------|-------------|
| [flash-pos](https://github.com/lnflash/flash-pos) | Merchant point-of-sale app |
| [flash-mobile](https://github.com/lnflash/flash-mobile) | Customer mobile wallet |
| [forge.flashapp.me](https://forge.flashapp.me) | Flash Cashu mint |
| [Cashu NUTs](https://github.com/cashubtc/nuts) | Cashu protocol specifications |
| [Numo](https://github.com/cashubtc/Numo) | Android Cashu NFC PoS (Profile A) |

---

## Need Help?

- **Protocol questions**: See [spec/NUT-XX.md](../spec/NUT-XX.md)
- **APDU details**: See [spec/APDU.md](../spec/APDU.md)
- **Contributing**: See [CONTRIBUTING.md](../CONTRIBUTING.md)
- **Issues**: [GitHub Issues](https://github.com/lnflash/cashu-javacard/issues)
