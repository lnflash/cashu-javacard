package me.flashapp.cashu;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * Cashu JavaCard Applet
 *
 * Implements NUT-XX Profile B (Bearer/Offline) for offline NFC payments.
 * Stores Cashu proofs in hardware-persistent EEPROM with non-resettable
 * spend counters. Provides secp256k1 signing for NUT-11 P2PK spending
 * conditions.
 *
 * AID: D2 76 00 00 85 01 02
 *
 * Command set:
 *   0x01  GET_INFO         — version, capabilities, slot stats
 *   0x10  GET_PUBKEY       — 33-byte compressed secp256k1 card pubkey
 *   0x11  GET_BALANCE      — sum of unspent proof amounts (uint32)
 *   0x12  GET_PROOF_COUNT  — count of non-empty slots
 *   0x13  GET_PROOF        — full proof data at slot index
 *   0x14  GET_SLOT_STATUS  — bulk 1-byte status for all slots
 *   0x20  SPEND_PROOF      — mark spent + return NUT-11 Schnorr signature
 *   0x21  SIGN_ARBITRARY   — sign 32-byte message (no proof consumed)
 *   0x30  LOAD_PROOF       — store new proof (PIN required if set)
 *   0x31  CLEAR_SPENT      — free spent slots (PIN required)
 *   0x40  VERIFY_PIN       — verify provisioning PIN
 *   0x41  SET_PIN          — set PIN (first-time, personalization only)
 *   0x42  CHANGE_PIN       — change PIN (current PIN session required)
 *   0x50  LOCK_CARD        — permanently disable write operations
 *
 * @see <a href="https://github.com/lnflash/cashu-javacard">cashu-javacard</a>
 * @see spec/APDU.md for full command reference
 * @see spec/NUT-XX.md for protocol specification
 */
public class CashuApplet extends Applet {

    // -------------------------------------------------------------------------
    // Applet version
    // -------------------------------------------------------------------------
    static final byte VERSION_MAJOR = (byte) 0x00;
    static final byte VERSION_MINOR = (byte) 0x01;

    // -------------------------------------------------------------------------
    // APDU instruction bytes
    // -------------------------------------------------------------------------
    static final byte INS_GET_INFO         = (byte) 0x01;
    static final byte INS_GET_PUBKEY       = (byte) 0x10;
    static final byte INS_GET_BALANCE      = (byte) 0x11;
    static final byte INS_GET_PROOF_COUNT  = (byte) 0x12;
    static final byte INS_GET_PROOF        = (byte) 0x13;
    static final byte INS_GET_SLOT_STATUS  = (byte) 0x14;
    static final byte INS_SPEND_PROOF      = (byte) 0x20;
    static final byte INS_SIGN_ARBITRARY   = (byte) 0x21;
    static final byte INS_LOAD_PROOF       = (byte) 0x30;
    static final byte INS_CLEAR_SPENT      = (byte) 0x31;
    static final byte INS_VERIFY_PIN       = (byte) 0x40;
    static final byte INS_SET_PIN          = (byte) 0x41;
    static final byte INS_CHANGE_PIN       = (byte) 0x42;
    static final byte INS_LOCK_CARD        = (byte) 0x50;

    // -------------------------------------------------------------------------
    // Proof slot layout constants (78 bytes per slot)
    // -------------------------------------------------------------------------
    static final short PROOF_SIZE          = (short) 78;
    static final short PROOF_STATUS_OFFSET = (short) 0;
    static final short PROOF_KEYSET_OFFSET = (short) 1;
    static final short PROOF_AMOUNT_OFFSET = (short) 9;
    static final short PROOF_SECRET_OFFSET = (short) 13;
    static final short PROOF_C_OFFSET      = (short) 45;

    static final short PROOF_DATA_LEN      = (short) 77;  // PROOF_SIZE - 1 (no status byte on input)

    static final byte STATUS_EMPTY   = (byte) 0x00;
    static final byte STATUS_UNSPENT = (byte) 0x01;
    static final byte STATUS_SPENT   = (byte) 0x02;

    static final short MAX_PROOFS = (short) 32;

    // -------------------------------------------------------------------------
    // Status words
    // -------------------------------------------------------------------------
    static final short SW_WRONG_PIN_REMAINING_2 = (short) 0x63C2;
    static final short SW_WRONG_PIN_REMAINING_1 = (short) 0x63C1;
    static final short SW_WRONG_PIN_REMAINING_0 = (short) 0x63C0;
    static final short SW_PIN_BLOCKED           = (short) 0x6983;
    static final short SW_PIN_NOT_SET           = (short) 0x6984;
    static final short SW_ALREADY_SPENT         = (short) 0x6985;
    static final short SW_PIN_ALREADY_SET       = (short) 0x6985; // reused — context differs
    static final short SW_SLOT_EMPTY            = (short) 0x6A88;
    static final short SW_NO_SPACE              = (short) 0x6A84;
    static final short SW_SLOT_OUT_OF_RANGE     = (short) 0x6A83;
    static final short SW_CRYPTO_ERROR          = (short) 0x6F00;
    static final short SW_CARD_LOCKED           = (short) 0x6985;

    // LOCK_CARD confirmation byte
    static final byte LOCK_CONFIRM_BYTE = (byte) 0xDE;

    // PIN constraints
    static final short PIN_MIN_LEN  = (short) 4;
    static final short PIN_MAX_LEN  = (short) 8;
    static final byte  PIN_MAX_TRIES = (byte) 3;

    // -------------------------------------------------------------------------
    // Persistent state (EEPROM)
    // -------------------------------------------------------------------------

    /** Proof storage: MAX_PROOFS * PROOF_SIZE bytes */
    private byte[] proofStorage;

    /** Card locked flag — once set to 1, write operations are disabled */
    private byte[] cardLocked;   // 1-byte array (persistent)

    /** PIN state: 0=unset, 1=set, 2=locked */
    private byte[] pinState;     // 1-byte array (persistent)

    /** The provisioning PIN (up to PIN_MAX_LEN bytes) */
    private OwnerPIN pin;

    // -------------------------------------------------------------------------
    // Card keypair (persistent, generated once on install)
    // -------------------------------------------------------------------------

    /**
     * The card's secp256k1 keypair.
     *
     * IMPLEMENTATION NOTE — secp256k1 curve initialisation:
     * Most JavaCard chips natively support NIST P-256 (ALG_EC_FP with
     * 256-bit field). secp256k1 uses the same field size but different
     * curve parameters (a=0, b=7, G_x, G_y, n, h). JavaCard's ECKey
     * API allows custom curve parameters via ECKey.setA/setB/setG/setR/setK.
     *
     * Required steps (see spec/SECP256K1.md for parameter constants):
     *   1. Allocate KeyPair with ALG_EC_FP + LENGTH_EC_FP_256
     *   2. Cast to ECPublicKey / ECPrivateKey
     *   3. Call setFieldFP(secp256k1_p, 0, 32)
     *   4. Call setA(secp256k1_a, 0, 32)  — a = 0
     *   5. Call setB(secp256k1_b, 0, 32)  — b = 7
     *   6. Call setG(secp256k1_G, 0, 65)  — uncompressed generator point
     *   7. Call setR(secp256k1_n, 0, 32)  — group order
     *   8. Call setK((short) 1)           — cofactor h = 1
     *   9. Call genKeyPair()
     *
     * Chip support varies:
     *   - JCOP4 SmartMX3: supports custom EC-FP curves, secp256k1 tested
     *   - Feitian JavaCard 3.0.4+: supports ALG_EC_FP custom params
     *   - jCardSim 3.x: supports ALG_EC_FP custom params (use for tests)
     *
     * This is the primary engineering challenge for Sprint 4 (ENG-181).
     */
    private KeyPair  cardKeyPair;
    private ECPrivateKey cardPrivKey;
    private ECPublicKey  cardPubKey;

    // -------------------------------------------------------------------------
    // Transient state (RAM, cleared on deselect)
    // -------------------------------------------------------------------------

    /** Set to 0x01 after successful VERIFY_PIN; cleared on deselect */
    private byte[] pinVerifiedFlag;

    /** Scratch buffer for crypto operations */
    private byte[] scratch;

    // -------------------------------------------------------------------------
    // Install / init
    // -------------------------------------------------------------------------

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CashuApplet().register();
    }

    private CashuApplet() {
        // Persistent storage
        proofStorage = new byte[(short)(MAX_PROOFS * PROOF_SIZE)];
        cardLocked   = new byte[1];
        pinState     = new byte[1];

        // PIN: max PIN_MAX_TRIES attempts, max PIN_MAX_LEN bytes
        pin = new OwnerPIN(PIN_MAX_TRIES, (byte) PIN_MAX_LEN);

        // Transient (RAM) — cleared every deselect
        pinVerifiedFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        scratch         = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        // Generate card keypair
        initCardKeypair();
    }

    /**
     * Initialises the secp256k1 card keypair.
     *
     * TODO (ENG-181): Set actual secp256k1 curve parameters before calling genKeyPair().
     * The stubs below will throw an exception on real hardware until the
     * curve parameters from spec/SECP256K1.md are wired in.
     *
     * For jCardSim testing, this will work after setSecp256k1Params() is implemented.
     */
    private void initCardKeypair() {
        cardKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        cardPrivKey = (ECPrivateKey) cardKeyPair.getPrivate();
        cardPubKey  = (ECPublicKey)  cardKeyPair.getPublic();
        // setSecp256k1Params(cardPubKey, cardPrivKey);  // TODO ENG-181
        cardKeyPair.genKeyPair();
    }

    // -------------------------------------------------------------------------
    // APDU dispatch
    // -------------------------------------------------------------------------

    @Override
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
            // Respond with version on SELECT
            buf[0] = VERSION_MAJOR;
            buf[1] = VERSION_MINOR;
            apdu.setOutgoingAndSend((short) 0, (short) 2);
            return;
        }

        if (buf[ISO7816.OFFSET_CLA] != (byte) 0xB0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            // Read commands (no auth)
            case INS_GET_INFO:         processGetInfo(apdu);        break;
            case INS_GET_PUBKEY:       processGetPubkey(apdu);      break;
            case INS_GET_BALANCE:      processGetBalance(apdu);     break;
            case INS_GET_PROOF_COUNT:  processGetProofCount(apdu);  break;
            case INS_GET_PROOF:        processGetProof(apdu);       break;
            case INS_GET_SLOT_STATUS:  processGetSlotStatus(apdu);  break;
            // Spend commands (no PIN — bearer semantics)
            case INS_SPEND_PROOF:      processSpendProof(apdu);     break;
            case INS_SIGN_ARBITRARY:   processSignArbitrary(apdu);  break;
            // Write commands (PIN required if set)
            case INS_LOAD_PROOF:       processLoadProof(apdu);      break;
            case INS_CLEAR_SPENT:      processClearSpent(apdu);     break;
            // Auth commands
            case INS_VERIFY_PIN:       processVerifyPin(apdu);      break;
            case INS_SET_PIN:          processSetPin(apdu);         break;
            case INS_CHANGE_PIN:       processChangePin(apdu);      break;
            // Admin
            case INS_LOCK_CARD:        processLockCard(apdu);       break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // -------------------------------------------------------------------------
    // Category 0x0x / 0x1x — Read commands
    // -------------------------------------------------------------------------

    private void processGetInfo(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short unspent = 0, spent = 0, empty = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            byte status = proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)];
            if      (status == STATUS_UNSPENT) unspent++;
            else if (status == STATUS_SPENT)   spent++;
            else                               empty++;
        }
        buf[0] = VERSION_MAJOR;
        buf[1] = VERSION_MINOR;
        buf[2] = (byte) MAX_PROOFS;
        buf[3] = (byte) unspent;
        buf[4] = (byte) spent;
        buf[5] = (byte) empty;
        // Capabilities: bit0=secp256k1 native (0 until ENG-181), bit1=Schnorr (0 until ENG-181), bit2=PIN
        buf[6] = (byte) 0x04; // PIN supported
        buf[7] = pinState[0];
        apdu.setOutgoingAndSend((short) 0, (short) 8);
    }

    private void processGetPubkey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short len = cardPubKey.getW(buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void processGetBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        long balance = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            short base = (short)(i * PROOF_SIZE);
            if (proofStorage[(short)(base + PROOF_STATUS_OFFSET)] == STATUS_UNSPENT) {
                balance += getUint32(proofStorage, (short)(base + PROOF_AMOUNT_OFFSET));
            }
        }
        buf[0] = (byte)((balance >> 24) & 0xFF);
        buf[1] = (byte)((balance >> 16) & 0xFF);
        buf[2] = (byte)((balance >> 8)  & 0xFF);
        buf[3] = (byte)( balance        & 0xFF);
        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    private void processGetProofCount(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short count = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            if (proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)] != STATUS_EMPTY) count++;
        }
        buf[0] = (byte) count;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void processGetProof(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short idx = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        if (idx >= MAX_PROOFS) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);

        short base = (short)(idx * PROOF_SIZE);
        if (proofStorage[(short)(base + PROOF_STATUS_OFFSET)] == STATUS_EMPTY) {
            ISOException.throwIt(SW_SLOT_EMPTY);
        }
        Util.arrayCopy(proofStorage, base, buf, (short) 0, PROOF_SIZE);
        apdu.setOutgoingAndSend((short) 0, PROOF_SIZE);
    }

    private void processGetSlotStatus(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        for (short i = 0; i < MAX_PROOFS; i++) {
            buf[i] = proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)];
        }
        apdu.setOutgoingAndSend((short) 0, MAX_PROOFS);
    }

    // -------------------------------------------------------------------------
    // Category 0x2x — Spend commands (no PIN — bearer)
    // -------------------------------------------------------------------------

    private void processSpendProof(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short idx = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        if (idx >= MAX_PROOFS) ISOException.throwIt(SW_SLOT_OUT_OF_RANGE);

        short base = (short)(idx * PROOF_SIZE);
        byte status = proofStorage[(short)(base + PROOF_STATUS_OFFSET)];

        if (status == STATUS_EMPTY)  ISOException.throwIt(SW_SLOT_EMPTY);
        if (status == STATUS_SPENT)  ISOException.throwIt(SW_ALREADY_SPENT);

        short msgLen = apdu.setIncomingAndReceive();
        if (msgLen != (short) 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // ATOMIC: mark spent BEFORE signing.
        // If signing fails, proof is still spent — this is intentional.
        // It prevents an attacker from aborting mid-command to reset the
        // spent flag. The proof is revoked regardless of signing outcome.
        proofStorage[(short)(base + PROOF_STATUS_OFFSET)] = STATUS_SPENT;

        // Sign the 32-byte message with card private key.
        // TODO (ENG-181): Replace with Schnorr signature implementation.
        // Schnorr sig = (R, s) where:
        //   k = random nonce
        //   R = k * G
        //   e = SHA256(R_x || pubkey || msg)
        //   s = k - e * privkey (mod n)
        short sigLen = signMessage(buf, ISO7816.OFFSET_CDATA, (short) 32, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    private void processSignArbitrary(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short msgLen = apdu.setIncomingAndReceive();
        if (msgLen != (short) 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short sigLen = signMessage(buf, ISO7816.OFFSET_CDATA, (short) 32, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    // -------------------------------------------------------------------------
    // Category 0x3x — Write commands (PIN required if set)
    // -------------------------------------------------------------------------

    private void processLoadProof(APDU apdu) {
        requireNotLocked();
        requirePinIfSet();

        // Find first empty slot
        short slot = -1;
        for (short i = 0; i < MAX_PROOFS; i++) {
            if (proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS_OFFSET)] == STATUS_EMPTY) {
                slot = i;
                break;
            }
        }
        if (slot < 0) ISOException.throwIt(SW_NO_SPACE);

        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen != PROOF_DATA_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        byte[] buf = apdu.getBuffer();
        short base = (short)(slot * PROOF_SIZE);
        proofStorage[(short)(base + PROOF_STATUS_OFFSET)] = STATUS_UNSPENT;
        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, proofStorage, (short)(base + PROOF_KEYSET_OFFSET), PROOF_DATA_LEN);

        buf[0] = (byte) slot;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void processClearSpent(APDU apdu) {
        requireNotLocked();
        requirePinIfSet();

        byte[] buf = apdu.getBuffer();
        short freed = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            short base = (short)(i * PROOF_SIZE);
            if (proofStorage[(short)(base + PROOF_STATUS_OFFSET)] == STATUS_SPENT) {
                Util.arrayFillNonAtomic(proofStorage, base, PROOF_SIZE, (byte) 0);
                freed++;
            }
        }
        buf[0] = (byte) freed;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // -------------------------------------------------------------------------
    // Category 0x4x — Authentication
    // -------------------------------------------------------------------------

    private void processVerifyPin(APDU apdu) {
        if (pinState[0] == (byte) 0) ISOException.throwIt(SW_PIN_NOT_SET);
        if (pin.getTriesRemaining() == 0) ISOException.throwIt(SW_PIN_BLOCKED);

        short pinLen = apdu.setIncomingAndReceive();
        if (pinLen < PIN_MIN_LEN || pinLen > PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] buf = apdu.getBuffer();
        boolean ok = pin.check(buf, ISO7816.OFFSET_CDATA, (byte) pinLen);
        if (!ok) {
            byte remaining = pin.getTriesRemaining();
            if (remaining == 0) {
                pinState[0] = (byte) 2; // locked
                ISOException.throwIt(SW_PIN_BLOCKED);
            }
            short sw = (short)(0x63C0 | (remaining & 0x0F));
            ISOException.throwIt(sw);
        }
        pinVerifiedFlag[0] = (byte) 1;
        // SW_NO_ERROR returned implicitly
    }

    private void processSetPin(APDU apdu) {
        requireNotLocked();
        if (pinState[0] != (byte) 0) ISOException.throwIt(SW_PIN_ALREADY_SET);

        short pinLen = apdu.setIncomingAndReceive();
        if (pinLen < PIN_MIN_LEN || pinLen > PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        byte[] buf = apdu.getBuffer();
        pin.update(buf, ISO7816.OFFSET_CDATA, (byte) pinLen);
        pinState[0] = (byte) 1;
    }

    private void processChangePin(APDU apdu) {
        requireNotLocked();
        requirePinVerified();

        short dataLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();
        short off = ISO7816.OFFSET_CDATA;

        // Data: 1-byte old-pin-len + old-pin + new-pin
        byte oldLen = buf[off++];
        if (oldLen < PIN_MIN_LEN || oldLen > PIN_MAX_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short newLen = (short)(dataLen - 1 - oldLen);
        if (newLen < PIN_MIN_LEN || newLen > PIN_MAX_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        // Verify old PIN
        boolean ok = pin.check(buf, off, oldLen);
        if (!ok) {
            byte remaining = pin.getTriesRemaining();
            short sw = (short)(0x63C0 | (remaining & 0x0F));
            ISOException.throwIt(sw);
        }
        off += oldLen;
        pin.update(buf, off, (byte) newLen);
    }

    // -------------------------------------------------------------------------
    // Category 0x5x — Admin
    // -------------------------------------------------------------------------

    private void processLockCard(APDU apdu) {
        requirePinIfSet();
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_P2] != LOCK_CONFIRM_BYTE) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        if (cardLocked[0] == (byte) 1) ISOException.throwIt(SW_CARD_LOCKED);
        cardLocked[0] = (byte) 1;
    }

    // -------------------------------------------------------------------------
    // Guard helpers
    // -------------------------------------------------------------------------

    private void requireNotLocked() {
        if (cardLocked[0] == (byte) 1) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }

    private void requirePinIfSet() {
        if (pinState[0] == (byte) 1 && pinVerifiedFlag[0] != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void requirePinVerified() {
        if (pinVerifiedFlag[0] != (byte) 1) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    // -------------------------------------------------------------------------
    // Crypto helpers
    // -------------------------------------------------------------------------

    /**
     * Signs a 32-byte message with the card private key.
     *
     * TODO (ENG-181): This is a PLACEHOLDER that returns 64 zero bytes.
     * Replace with Schnorr signature:
     *   sig = Schnorr.sign(cardPrivKey, msg[msgOff..msgOff+32])
     *
     * Schnorr signature (BIP-340 compatible, 64 bytes = R_x || s):
     *   k  = deterministic nonce (RFC 6979 or hardware RNG)
     *   R  = k * G
     *   e  = SHA256(bytes(R_x) || bytes(pubkey) || msg)
     *   s  = (k - e * privkey) mod n
     *   sig = bytes(R_x) || bytes(s)   [32 + 32 = 64 bytes]
     *
     * @param msg    source buffer containing message
     * @param msgOff offset of message in source buffer
     * @param msgLen message length (must be 32)
     * @param out    output buffer
     * @param outOff offset in output buffer
     * @return length of signature (64)
     */
    private short signMessage(byte[] msg, short msgOff, short msgLen, byte[] out, short outOff) {
        // PLACEHOLDER — replace with Schnorr in ENG-181
        Util.arrayFillNonAtomic(out, outOff, (short) 64, (byte) 0);
        return (short) 64;
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private long getUint32(byte[] buf, short offset) {
        return ((long)(buf[offset]              & 0xFF) << 24)
             | ((long)(buf[(short)(offset + 1)] & 0xFF) << 16)
             | ((long)(buf[(short)(offset + 2)] & 0xFF) << 8)
             |  (long)(buf[(short)(offset + 3)] & 0xFF);
    }
}
