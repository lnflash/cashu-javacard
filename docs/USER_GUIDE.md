# User Guide: Cashu JavaCard NFC Payments

This guide explains how to use a Cashu JavaCard for offline NFC payments — loading money onto the card and tapping to pay at a merchant terminal.

## What Is a Cashu JavaCard?

A Cashu JavaCard is a physical NFC card (like a debit card) that holds **Bitcoin ecash tokens** (Cashu proofs) in a tamper-resistant chip. You can:

- **Load** funds onto the card from your Flash wallet (online)
- **Pay** by tapping the card at a merchant's point-of-sale terminal (offline — no internet needed)
- **Receive** change back to your card on your next top-up

The card works like physical cash: if you lose it, the funds on it are gone. Keep your balance to a level you're comfortable carrying.

### How It Works (30-Second Version)

1. You open the Flash app and top up your card over NFC — this loads signed Cashu proofs onto the chip.
2. At a store, you tap your card on the merchant's POS terminal.
3. The terminal reads the proofs directly from the card — **no internet connection needed** at point of sale.
4. The card cryptographically signs the payment (irreversibly marking the proofs as spent).
5. The merchant later redeems the proofs online with the Cashu mint.

---

## Supported Cards

| Card | Status | Price | Notes |
|------|--------|-------|-------|
| **Feitian JavaCard 3.0.4** | ✅ Available now | ~$2/card (volume) | Primary target for v1. Widely available. |
| **NXP JCOP4 (SmartMX3)** | ✅ Available | ~$5/card | CC EAL 5+ certified. Higher security for larger balances. |
| NXP NTAG 424 DNA | ❌ Not supported | — | Insufficient memory, no EC crypto capability. |
| Generic JavaCard 3.0.1+ | ⚠️ Untested | Varies | May work if the chip supports `ALG_EC_SVDP_DH_PLAIN_XY`. |

**Recommendation:** Start with Feitian JavaCard 3.0.4 for personal use. For higher-value cards, use NXP JCOP4 SmartMX3 with its EAL 5+ tamper resistance.

---

## Getting a Card

1. **Purchase** a compatible JavaCard (Feitian JavaCard 3.0.4 recommended).
2. **Load the applet** onto the card — see [Loading the Applet](#loading-the-applet-onto-a-javacard) below.
3. **Set a PIN** (optional but recommended for higher balances) — the PIN protects provisioning (loading funds), not spending. Physical possession authorizes payment, just like cash.

---

## Loading the Applet onto a JavaCard

This section covers installing the Cashu applet software onto a blank JavaCard. You only need to do this once per card.

### What You Need

| Item | Details |
|------|---------|
| **Blank JavaCard** | Feitian JavaCard 3.0.4 or NXP JCOP4 |
| **NFC card reader** | Any ISO 7816-4 compatible USB reader (e.g., ACR122U, HID Omnikey) |
| **Computer** | macOS, Linux, or Windows with JDK 11+ |
| **GlobalPlatformPro** | Tool for installing applets on JavaCards ([install guide](https://github.com/martinpaljak/GlobalPlatformPro)) |

### Step 1: Install Prerequisites

**Java 11+:**

```bash
# macOS
brew install openjdk@17

# Ubuntu/Debian
sudo apt install openjdk-17-jdk

# Verify
java -version
```

**GlobalPlatformPro (gp):**

```bash
# Download gp.jar
curl -L https://github.com/martinpaljak/GlobalPlatformPro/releases/latest/download/gp.jar \
     -o /usr/local/bin/gp.jar

# Create wrapper script
cat > /usr/local/bin/gp << 'EOF'
#!/bin/sh
exec java -jar /usr/local/bin/gp.jar "$@"
EOF
chmod +x /usr/local/bin/gp
```

**NFC reader drivers:**

```bash
# macOS
brew install pcsc-lite

# Ubuntu/Debian
sudo apt install pcscd libpcsclite-dev
```

### Step 2: Build the Applet

```bash
git clone https://github.com/lnflash/cashu-javacard.git
cd cashu-javacard/applet

# Build the .cap file
ant cap

# Output: target/cashu-javacard-0.1.0.cap
```

> **Note:** First build downloads the JavaCard SDK (~40 MB). Subsequent builds use the cache.

**For hardware deployment** (real cards, not testing), edit `CashuApplet.java` before building:

```java
// Change this line from false to true:
static final boolean HARDWARE = true;
```

### Step 3: Connect the Reader

1. Plug the NFC reader into your computer.
2. Place the blank JavaCard on the reader.
3. Verify the connection:

```bash
gp --list

# Expected output (fresh card):
# ISD: A000000151000000 (OP_READY)
```

### Step 4: Install the Applet

```bash
# Install
gp --install target/cashu-javacard-0.1.0.cap

# Verify
gp --list
# Expected: APP: D276000085010201 (SELECTABLE)
```

### Step 5: Verify It Works

```bash
# SELECT the applet
gp --apdu 00A4040007D2760000850102
# Response: 0000 9000 ✓

# Get card info
gp --apdu B0010000
# Response: 00 01 20 00 00 00 06 9000
#   (v0.1, 32 slots, 0 unspent, 0 spent)

# Get card public key
gp --apdu B0100000
# Response: 33-byte compressed secp256k1 pubkey + 9000 ✓
```

Your card is ready! You can now load it with funds.

---

## Loading Funds (Top-Up)

Funding your card requires an internet connection. You use the Flash mobile app or Flash POS to transfer Cashu proofs onto the card over NFC.

### How It Works

```
┌──────────────────────────────────────────────────────────┐
│  Your phone (Flash app)          NFC card                │
│  1. Opens Cashu mint connection                           │
│  2. Requests proofs locked to your card's public key      │
│  3. Tap card → writes proofs over NFC                     │
│  4. Card confirms: "Loaded 500 sats to slot 3"           │
└──────────────────────────────────────────────────────────┘
```

### Steps

1. Open the Flash mobile app on your phone.
2. Navigate to **Card Top-Up** (or tap an NFC reader at a Flash POS terminal).
3. Enter the amount you want to load.
4. The app connects to the Cashu mint and generates proofs locked to your card's public key.
5. Hold your card against the phone's NFC area.
6. The app writes the proofs to the card — this takes 2–5 seconds depending on the number of proofs.
7. Done! Your card balance is updated.

### What Happens on the Card

During top-up, the card:
1. Receives each proof (keyset ID, amount, secret, mint signature).
2. Stores it in the next available slot (up to 32 slots).
3. Garbage-collects any previously spent slots (`CLEAR_SPENT`) to free space.

---

## Making a Payment (Tap to Pay)

Payments are **fully offline** — no internet is needed at the point of sale.

### How It Works

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                    │
│  STEP 1: TAP                                                       │
│  Customer holds card against merchant's POS terminal.              │
│                                                                    │
│  STEP 2: READ BALANCE                                              │
│  Terminal reads card balance (GET_BALANCE).                        │
│  If balance < purchase amount → abort.                             │
│                                                                    │
│  STEP 3: SELECT PROOFS                                             │
│  Terminal finds unspent proofs totaling ≥ purchase amount.         │
│                                                                    │
│  STEP 4: SPEND                                                     │
│  For each selected proof:                                          │
│    • Card marks proof as SPENT (irreversible — hardware enforced)  │
│    • Card signs the payment with its private key (Schnorr)         │
│    • Terminal receives the signature                               │
│                                                                    │
│  STEP 5: CONFIRM                                                   │
│  Terminal shows "Payment accepted — 100 sats"                      │
│  No internet required.                                             │
│                                                                    │
│  STEP 6: SETTLE (LATER)                                            │
│  When online, merchant redeems proofs with the Cashu mint.         │
│                                                                    │
└──────────────────────────────────────────────────────────────────┘
```

### Step-by-Step (User Perspective)

1. The merchant tells you the total (e.g., "500 sats").
2. You hold your card against the POS terminal's NFC reader.
3. The terminal beeps and shows "Payment accepted."
4. Done! Your card balance decreases by 500 sats.

The entire process takes **under 1 second** once the card is in range.

### Important Notes

- **Payments are irreversible.** Once you tap to confirm, the proofs are permanently marked as spent on the card. There is no undo.
- **No change is given** during an offline payment. If your card has 1,000 sats and you pay 500, the merchant collects all selected proofs (potentially up to 1,000). Denomination-aware selection minimizes overpayment.
- **Change can be credited** during your next online top-up session.

---

## Receiving Change

When the merchant settles your payment online, if there was overpayment, they can credit change back to your card:

1. The merchant redeems your proofs with the mint.
2. The mint issues new proofs for the change amount.
3. On your next visit (or via the Flash app), the change proofs are loaded back onto your card via `LOAD_PROOF`.

This requires an online session — change is not instant during offline payments.

---

## Security & Safety

### What Protects Your Card

| Protection | How |
|-----------|-----|
| **Hardware single-spend** | Each proof can only be marked spent once. This is enforced by the chip — even with physical access, you cannot un-spend a proof. |
| **On-chip key generation** | The card's private key is generated inside the chip and never leaves it. Cloning the EEPROM does not clone the key. |
| **PIN on provisioning** | If you set a PIN, it protects loading funds (not spending). This prevents unauthorized top-ups. |
| **Bearer semantics** | Physical possession = authorization to spend. Same as cash. |

### Best Practices

- **Keep balances modest.** Treat the card like a physical wallet — don't load more than you'd carry in cash.
- **Set a PIN** if your card supports it (recommended for balances over ~$10 equivalent).
- **Report lost cards** to the merchant network if applicable. The card cannot be deactivated remotely (bearer instrument).
- **Top up regularly** rather than loading a large amount once. This limits your exposure.

### What the Card Cannot Do

- ❌ **Remote deactivation** — there is no "freeze card" feature (bearer instrument).
- ❌ **Balance recovery** — if the card is lost, the proofs on it are unrecoverable.
- ❌ **PIN on spending** — the base profile (Profile B) does not require PIN to spend. Profile B+ variants can add this.

---

## APDU Command Reference (Developer Summary)

For developers integrating with the card, here is a quick command summary. See [`spec/APDU.md`](../spec/APDU.md) for the full reference.

| Command | INS | Auth | Description |
|---------|-----|------|-------------|
| `SELECT` | 0xA4 | None | Select the Cashu applet (AID: `D2 76 00 00 85 01 02`) |
| `GET_INFO` | 0x01 | None | Version, capabilities, slot statistics |
| `GET_PUBKEY` | 0x10 | None | Card's 33-byte compressed secp256k1 public key |
| `GET_BALANCE` | 0x11 | None | Total unspent balance (4-byte uint32) |
| `GET_PROOF_COUNT` | 0x12 | None | Number of non-empty proof slots |
| `GET_PROOF` | 0x13 | None | Full proof data at a slot index |
| `GET_SLOT_STATUS` | 0x14 | None | Bulk status for all 32 slots |
| `SPEND_PROOF` | 0x20 | None* | Mark proof spent + return Schnorr signature |
| `SIGN_ARBITRARY` | 0x21 | None | Sign any 32-byte message (no proof consumed) |
| `LOAD_PROOF` | 0x30 | PIN | Store a new proof on the card |
| `CLEAR_SPENT` | 0x31 | PIN | Garbage-collect spent slots |
| `VERIFY_PIN` | 0x40 | — | Verify the provisioning PIN |
| `SET_PIN` | 0x41 | — | Set PIN (one-time, personalization) |
| `CHANGE_PIN` | 0x42 | PIN session | Change PIN |
| `LOCK_CARD` | 0x50 | PIN | Permanently disable writes (irreversible) |

*\*SPEND_PROOF has no auth in Profile B (bearer semantics). Profile B+ variants require PIN.*

---

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| "Insufficient balance" | Card doesn't have enough unspent proofs | Top up via the Flash app |
| "No space" on top-up | All 32 slots are full (spent + unspent) | Run `CLEAR_SPENT` to reclaim slots |
| Card not detected | Reader not compatible or card not placed correctly | Reposition card; verify reader supports ISO 14443-4 |
| PIN locked | 3 failed PIN attempts | Card is permanently locked for writes; unspent proofs can still be spent |
| Applet won't install | Card doesn't support JavaCard 3.0.4+ | Use a Feitian JavaCard 3.0.4 or NXP JCOP4 |

---

## Further Reading

- [Protocol Specification (NUT-XX)](../spec/NUT-XX.md) — full technical protocol spec
- [APDU Command Reference](../spec/APDU.md) — complete command set with byte-level detail
- [Architecture](ARCHITECTURE.md) — on-card data model and key management
- [Hardware Deployment](HARDWARE_DEPLOYMENT.md) — building and deploying to physical cards
- [Contributing](../CONTRIBUTING.md) — development setup and PR process
