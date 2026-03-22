# User Guide — Cashu JavaCard

Welcome to **cashu-javacard**. This guide explains what the project is, how to get started, and how payments work — without assuming you're a developer.

---

## What Is cashu-javacard?

**cashu-javacard** is a small applet (a tiny program) that runs inside an NFC smart card. It turns a plastic card into a **digital cash card** — like a prepaid debit card, but powered by [Cashu ecash](https://cashu.space) and Bitcoin's Lightning Network.

When you load Cashu tokens onto the card, they are stored in the card's secure hardware chip. You can then **tap the card** at a merchant's point-of-sale terminal to make a payment — no phone, no internet, no app required at the moment of payment.

### Key Features

| Feature | Description |
|---------|-------------|
| **Offline payments** | Pay by tapping the card — no internet needed at checkout |
| **Hardware-secured** | Your private key lives inside the card chip and never leaves it |
| **Single-spend guarantee** | Once a token is spent, it's permanently marked — no double-spending |
| **Bearer instrument** | Whoever holds the card holds the value (like physical cash) |
| **Lightning-backed** | Cards are funded and redeemed via Bitcoin's Lightning Network |

---

## How It Works

There are two main phases: **top-up** (loading money onto the card) and **payment** (spending it).

### Top-Up (Online)

```
┌─────────────────────────────────────────────────────────┐
│  You (or a POS terminal) connect to a Cashu mint        │
│  via Lightning Network → receive Cashu proofs            │
│  → tap your card → proofs are written to the chip       │
└─────────────────────────────────────────────────────────┘
```

1. You (or a merchant terminal) pay a Lightning invoice
2. The Cashu mint issues cryptographic proofs (digital tokens)
3. Your card is tapped on an NFC reader
4. The proofs are loaded onto the card's secure chip

### Payment (Offline)

```
┌─────────────────────────────────────────────────────────┐
│  You tap your card at a merchant's NFC terminal          │
│  Terminal reads proofs from the card (no internet)       │
│  Card signs the transaction with its on-chip key         │
│  Terminal confirms payment — done!                       │
│  Later: merchant redeems the proofs online with the mint │
└─────────────────────────────────────────────────────────┘
```

1. You tap the card on the merchant's terminal
2. The terminal reads the available balance from the card
3. You confirm the amount
4. The card marks the spent tokens as used (irreversible) and signs the transaction
5. The merchant stores the signed proofs and redeems them later when online

---

## Card Compatibility

The applet runs on **JavaCard 3.0.4+** smart cards with NFC and secp256k1 cryptographic support.

### Supported Cards

| Card | Status | Approx. Cost | Notes |
|------|--------|-------------|-------|
| **Feitian JavaCard 3.0.4** | ✅ Recommended | ~$2/card (volume) | Primary target. Widely available. |
| **NXP JCOP4 SmartMX3** | ✅ Supported | ~$5/card | CC EAL 5+ certified (higher security). Used in banking-grade applications. |

### Not Compatible

| Card | Why Not |
|------|---------|
| NXP NTAG 424 DNA | Insufficient memory; no secp256k1 EC crypto |
| MIFARE Classic/Ultralight | Not a JavaCard; no applet support |
| NTAG 213/215/216 | Passive NFC tags; no computation capability |
| JavaCard 2.2.x | No `int` type; lacks required ECDH APIs |

### Where to Buy

- **Feitian JavaCard 3.0.4**: Available from [Feitian](https://www.ftsafe.com/Products/Java_Card) or AliExpress sellers (search "Feitian JavaCard NFC")
- **NXP JCOP4**: Contact [NXP](https://www.nxp.com/products/security-and-authentication/secure-service-2go/jcop-4) or authorized distributors

### Requirements for Your NFC Reader

To interact with the card (for top-up or as a merchant), you need:

- **NFC reader** supporting ISO 14443-4 (Type A or B)
  - Most modern Android phones with NFC work
  - USB NFC readers (ACR122U, Identiv SCR3310, etc.)
- **Software** that can send APDU commands — such as [flash-pos](https://github.com/lnflash/flash-pos) or the `gp` CLI tool (see below)

---

## Getting Your Card Set Up

### Prerequisites

Before you begin, you need:

| Item | Purpose |
|------|---------|
| A compatible JavaCard (see above) | The card itself |
| An NFC reader (USB or phone) | To communicate with the card |
| JDK 11+ | To build the applet |
| [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro) (`gp`) | To install the applet onto the card |

### Step 1: Install GlobalPlatformPro

GlobalPlatformPro (`gp`) is a command-line tool for managing JavaCard applications.

```bash
# Download gp.jar
curl -L https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar \
     -o /usr/local/bin/gp.jar

# Create a wrapper script
cat > /usr/local/bin/gp << 'EOF'
#!/bin/sh
exec java -jar /usr/local/bin/gp.jar "$@"
EOF
chmod +x /usr/local/bin/gp
```

### Step 2: Build the Applet

```bash
git clone https://github.com/lnflash/cashu-javacard.git
cd cashu-javacard/applet

# Build the .cap file (JavaCard applet package)
ant cap

# Output: target/cashu-javacard-0.1.0.cap
```

> **First build** takes longer — ant-javacard downloads the JavaCard 3.0.4 SDK (~40 MB).

### Step 3: Connect Your Card

Insert the JavaCard into your NFC reader, then verify the connection:

```bash
gp --list
```

Expected output on a fresh card:
```
ISD: A000000151000000 (OP_READY)
```

### Step 4: Install the Applet

```bash
gp --install target/cashu-javacard-0.1.0.cap

# Verify installation
gp --list
```

Expected output:
```
APP: D276000085010201 (SELECTABLE)
```

### Step 5: Test the Card

```bash
# Select the applet
gp --apdu 00A4040007D2760000850102
# Response: 0000 9000  ✅

# Check card info
gp --apdu B0010000
# Response: 00 01 20 00 00 00 06  (v0.1, 32 slots, all empty)

# Get the card's public key
gp --apdu B0100000
# Response: 33-byte compressed secp256k1 public key + 9000
```

Your card is now ready to receive Cashu proofs.

### Step 6: Fund the Card

Use [flash-pos](https://github.com/lnflash/flash-pos) or [flash-mobile](https://github.com/lnflash/flash-mobile) to:

1. Pay a Lightning invoice (this gets Cashu proofs from the mint)
2. Tap your card on the NFC reader
3. Proofs are loaded onto the card — your balance is updated

You can verify the balance:
```bash
gp --apdu B0110000
# Response: 4-byte balance (big-endian uint32) + 9000
```

---

## NFC Payment Flow — Detailed Walkthrough

Here's exactly what happens when a customer taps their card at a merchant terminal:

```
  Customer                    POS Terminal                      Card
     │                              │                             │
     │  1. Tap card                 │                             │
     ├─────────────────────────────>│                             │
     │                              │  2. SELECT APPLICATION      │
     │                              ├────────────────────────────>│
     │                              │  ← version + 9000          │
     │                              │                             │
     │                              │  3. GET_BALANCE             │
     │                              ├────────────────────────────>│
     │                              │  ← 2500 sats + 9000        │
     │                              │                             │
     │                              │  4. GET_SLOT_STATUS         │
     │                              ├────────────────────────────>│
     │                              │  ← [01,01,02,00,...]        │
     │                              │                             │
     │                              │  5. GET_PROOF (slot 0)      │
     │                              ├────────────────────────────>│
     │                              │  ← proof data (78 bytes)    │
     │                              │                             │
     │  6. Confirm amount?          │                             │
     │<─────────────────────────────┤                             │
     │  7. Yes                      │                             │
     ├─────────────────────────────>│                             │
     │                              │                             │
     │                              │  8. SPEND_PROOF (slot 0)    │
     │                              │     + msg = SHA256(secret)  │
     │                              ├────────────────────────────>│
     │                              │     Card marks slot SPENT   │
     │                              │     Card signs with privkey │
     │                              │  ← 64-byte Schnorr sig      │
     │                              │                             │
     │  9. "Payment accepted ✓"     │                             │
     │<─────────────────────────────┤                             │
     │                              │                             │
     │                              │  [Later, online:]           │
     │                              │  POST /v1/melt with proof   │
     │                              │  + signature to mint        │
     │                              │  ← Mint verifies & settles  │
```

### What the Terminal Does Behind the Scenes

1. **Read available balance** — checks how much value is on the card
2. **Select which proofs to spend** — picks proofs that sum to ≥ the payment amount
3. **Request spend authorization** — the card marks proofs as spent and signs them
4. **Show confirmation** — "Payment accepted"
5. **Settle later** — when internet is available, the terminal redeems the signed proofs with the Cashu mint

### Offline Capability

The entire flow from step 2 to step 9 works **without internet**. The merchant only needs connectivity later to redeem the proofs with the mint. This makes cashu-javacard ideal for:

- Markets and fairs with poor connectivity
- Rural areas
- Disaster/emergency situations
- Any scenario where "tap to pay" should work regardless of network

---

## Reinstalling or Upgrading

The applet has no over-the-air upgrade path. To upgrade or reset:

```bash
# Delete the applet (erases all data, including proofs and keys!)
gp --delete D276000085010201   # applet AID
gp --delete D276000085010200   # package AID

# Reinstall fresh
gp --install target/cashu-javacard-0.1.0.cap
```

> ⚠️ **Warning**: Deleting the applet wipes all proofs and the card's keypair. Any remaining balance on the card is lost. Only do this if you've spent all proofs or are starting fresh.

---

## Security Considerations

- **Treat the card like cash.** Whoever holds the card can spend its balance. There's no "login" by default.
- **The private key never leaves the chip.** Even if someone copies the card's memory, they can't forge valid signatures.
- **Spent proofs can't be unspent.** The hardware enforces a one-way spend flag — no software trick can reverse it.
- **Set a PIN for high-value cards.** Profile B+ supports PIN-gated spending if you want extra protection.
- **Choose certified hardware.** NXP JCOP4 (CC EAL 5+) offers stronger protection against physical tampering than generic cards.

---

## FAQ

**Q: Can I use my phone instead of a card?**
A: Yes, if your phone can run a JavaCard applet (e.g., via a SIM-based JavaCard SE). Most phones cannot host JavaCard applets directly, but the [flash-mobile](https://github.com/lnflash/flash-mobile) app provides a software wallet alternative.

**Q: What happens if I lose the card?**
A: The balance is lost, just like losing physical cash. This is by design — the card is a bearer instrument. Keep balances at a level you're comfortable carrying.

**Q: How many payments can a card hold?**
A: 32 proof slots. Each payment typically consumes 1–3 slots (depending on denominations). Use `CLEAR_SPENT` to reclaim spent slots between top-ups.

**Q: What denominations are used?**
A: Power-of-2 denominations (1, 2, 4, 8, 16, 32, ... sats) to minimize overpayment and maximize slot efficiency.

**Q: Can I use this with any Cashu mint?**
A: Yes, any mint supporting NUT-11 (P2PK) spending conditions works. The [Flash mint](https://forge.flashapp.me) is the reference implementation.

---

## Further Reading

- [Protocol Specification (NUT-XX)](../spec/NUT-XX.md) — full technical specification
- [APDU Command Reference](../spec/APDU.md) — complete command set for developers
- [Architecture](./ARCHITECTURE.md) — on-card data model and internals
- [Hardware Deployment](./HARDWARE_DEPLOYMENT.md) — building and flashing cards
- [Cashu Protocol](https://cashu.space) — the ecash protocol this project implements
- [Cashu NUTs](https://github.com/cashubtc/nuts) — all protocol specifications

---

## Related Projects

| Project | Description |
|---------|-------------|
| [flash-pos](https://github.com/lnflash/flash-pos) | Merchant point-of-sale app |
| [flash-mobile](https://github.com/lnflash/flash-mobile) | Customer mobile wallet |
| [forge.flashapp.me](https://forge.flashapp.me) | Flash Cashu mint (Nutshell 0.18.0) |
| [Numo](https://github.com/cashubtc/Numo) | Android Cashu NFC POS (Profile A) |

---

## Need Help?

- Open an [issue on GitHub](https://github.com/lnflash/cashu-javacard/issues)
- Read the [CONTRIBUTING guide](../CONTRIBUTING.md) for development setup
- Check the [spec](../spec/NUT-XX.md) for protocol-level questions
