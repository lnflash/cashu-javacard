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
    // secp256k1 curve parameters (JavaCard byte arrays)
    // Used by setSecp256k1Params() — hardware-compatible code.
    // -------------------------------------------------------------------------

    /** secp256k1 field prime p */
    private static final byte[] SECP256K1_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
    };

    /** secp256k1 a = 0 */
    private static final byte[] SECP256K1_A = new byte[32];

    /** secp256k1 b = 7 */
    private static final byte[] SECP256K1_B = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,7
    };

    /** secp256k1 uncompressed generator G = 04 || Gx || Gy (65 bytes) */
    private static final byte[] SECP256K1_G = {
        (byte)0x04,
        // Gx
        (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
        (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
        (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
        (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
        // Gy
        (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
        (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
        (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
        (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
    };

    /** secp256k1 group order n */
    private static final byte[] SECP256K1_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };

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

    private KeyPair     cardKeyPair;
    private ECPrivateKey cardPrivKey;
    private ECPublicKey  cardPubKey;

    // -------------------------------------------------------------------------
    // Hardware Schnorr engine (ENG-182)
    //
    // HARDWARE = true  → uses SchnorrHW (JavaCard-native, no BigInteger)
    //                    Required for real .cap deployment.
    // HARDWARE = false → uses signMessage() BigInteger simulation (jCardSim only)
    //                    Set false for test builds / jCardSim.
    // -------------------------------------------------------------------------
    static final boolean HARDWARE = false; // ← flip to true for .cap build
    private SchnorrHW schnorrHW;           // null when HARDWARE=false

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
        proofStorage    = new byte[(short)(MAX_PROOFS * PROOF_SIZE)];
        cardLocked      = new byte[1];
        pinState        = new byte[1];
        pin             = new OwnerPIN(PIN_MAX_TRIES, (byte) PIN_MAX_LEN);
        pinVerifiedFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        scratch         = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        initCardKeypair();

        if (HARDWARE) {
            schnorrHW = new SchnorrHW(SECP256K1_G, SECP256K1_P,
                                      SECP256K1_A, SECP256K1_B, SECP256K1_N);
            schnorrHW.init();
        }
    }

    /**
     * Initialises the secp256k1 card keypair.
     *
     * Sets standard secp256k1 curve parameters on the key objects before
     * generating a random key pair.
     *
     * Hardware notes:
     * - JCOP4 SmartMX3, Feitian JavaCard 3.0.4+: support custom EC-FP curves
     * - jCardSim 3.x: supported
     */
    private void initCardKeypair() {
        cardKeyPair  = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        cardPrivKey  = (ECPrivateKey) cardKeyPair.getPrivate();
        cardPubKey   = (ECPublicKey)  cardKeyPair.getPublic();
        setSecp256k1Params(cardPubKey, cardPrivKey);
        cardKeyPair.genKeyPair();
    }

    /**
     * Sets secp256k1 curve parameters on a JavaCard EC key pair.
     *
     * This method uses only the standard JavaCard ECKey API and is
     * hardware-compatible (JCOP4, Feitian, jCardSim).
     *
     * @param pub  EC public key to configure
     * @param priv EC private key to configure
     */
    private void setSecp256k1Params(ECPublicKey pub, ECPrivateKey priv) {
        pub.setFieldFP(SECP256K1_P, (short) 0, (short) 32);
        pub.setA(SECP256K1_A, (short) 0, (short) 32);
        pub.setB(SECP256K1_B, (short) 0, (short) 32);
        pub.setG(SECP256K1_G, (short) 0, (short) 65);
        pub.setR(SECP256K1_N, (short) 0, (short) 32);
        pub.setK((short) 1);

        priv.setFieldFP(SECP256K1_P, (short) 0, (short) 32);
        priv.setA(SECP256K1_A, (short) 0, (short) 32);
        priv.setB(SECP256K1_B, (short) 0, (short) 32);
        priv.setG(SECP256K1_G, (short) 0, (short) 65);
        priv.setR(SECP256K1_N, (short) 0, (short) 32);
        priv.setK((short) 1);
    }

    // -------------------------------------------------------------------------
    // APDU dispatch
    // -------------------------------------------------------------------------

    @Override
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
            buf[0] = VERSION_MAJOR;
            buf[1] = VERSION_MINOR;
            apdu.setOutgoingAndSend((short) 0, (short) 2);
            return;
        }

        if (buf[ISO7816.OFFSET_CLA] != (byte) 0xB0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET_INFO:         processGetInfo(apdu);        break;
            case INS_GET_PUBKEY:       processGetPubkey(apdu);      break;
            case INS_GET_BALANCE:      processGetBalance(apdu);     break;
            case INS_GET_PROOF_COUNT:  processGetProofCount(apdu);  break;
            case INS_GET_PROOF:        processGetProof(apdu);       break;
            case INS_GET_SLOT_STATUS:  processGetSlotStatus(apdu);  break;
            case INS_SPEND_PROOF:      processSpendProof(apdu);     break;
            case INS_SIGN_ARBITRARY:   processSignArbitrary(apdu);  break;
            case INS_LOAD_PROOF:       processLoadProof(apdu);      break;
            case INS_CLEAR_SPENT:      processClearSpent(apdu);     break;
            case INS_VERIFY_PIN:       processVerifyPin(apdu);      break;
            case INS_SET_PIN:          processSetPin(apdu);         break;
            case INS_CHANGE_PIN:       processChangePin(apdu);      break;
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
        // Capabilities flags:
        //   bit0 = secp256k1 native key generation (set — ENG-181 complete)
        //   bit1 = BIP-340 Schnorr signing (set — ENG-181 complete)
        //   bit2 = PIN supported (always set)
        // Note: bits 0+1 are marked as simulation-quality for jCardSim.
        //   Hardware deployment (ENG-182) requires Schnorr replacement.
        buf[6] = (byte) 0x07; // secp256k1 + Schnorr + PIN
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
        // If signing fails, the proof is still consumed — this prevents an
        // attacker from aborting the transaction to reset the spent flag.
        proofStorage[(short)(base + PROOF_STATUS_OFFSET)] = STATUS_SPENT;

        short sigLen = doSign(buf, ISO7816.OFFSET_CDATA, (short) 32, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    private void processSignArbitrary(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short msgLen = apdu.setIncomingAndReceive();
        if (msgLen != (short) 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        short sigLen = doSign(buf, ISO7816.OFFSET_CDATA, (short) 32, buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, sigLen);
    }

    // -------------------------------------------------------------------------
    // Category 0x3x — Write commands (PIN required if set)
    // -------------------------------------------------------------------------

    private void processLoadProof(APDU apdu) {
        requireNotLocked();
        requirePinIfSet();

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
                pinState[0] = (byte) 2;
                ISOException.throwIt(SW_PIN_BLOCKED);
            }
            short sw = (short)(0x63C0 | (remaining & 0x0F));
            ISOException.throwIt(sw);
        }
        pinVerifiedFlag[0] = (byte) 1;
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

        byte oldLen = buf[off++];
        if (oldLen < PIN_MIN_LEN || oldLen > PIN_MAX_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short newLen = (short)(dataLen - 1 - oldLen);
        if (newLen < PIN_MIN_LEN || newLen > PIN_MAX_LEN) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

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
    // Signing dispatch — hardware vs. simulation
    // -------------------------------------------------------------------------

    /**
     * Route BIP-340 signing to hardware (SchnorrHW) or JVM simulation.
     * HARDWARE flag controls which path is compiled active.
     */
    private short doSign(byte[] msg, short msgOff, short msgLen,
                         byte[] out, short outOff) {
        if (HARDWARE) {
            // Hardware path: JavaCard-native crypto, no BigInteger.
            // SchnorrHW uses ALG_EC_SVDP_DH_PLAIN_XY + int[] modular arithmetic.
            return schnorrHW.sign(cardPrivKey, cardPubKey, msg, msgOff, out, outOff);
        } else {
            // Simulation path: BigInteger-based, correct on JVM / jCardSim.
            return signMessage(msg, msgOff, msgLen, out, outOff);
        }
    }

    // -------------------------------------------------------------------------
    // Crypto — BIP-340 Schnorr signature (SIMULATION — JVM / jCardSim only)
    //
    // ⚠️  Uses java.math.BigInteger, java.security.MessageDigest, java.util.Arrays,
    // and System.arraycopy — NONE of which are available in the JavaCard runtime.
    //
    // This implementation is correct for jCardSim testing on the JVM.
    // For hardware deployment: HARDWARE=true routes through SchnorrHW instead.
    // -------------------------------------------------------------------------

    /**
     * BIP-340 Schnorr sign: sig = (R.x || s), 64 bytes.
     *
     * Algorithm:
     *   1. If P.y is odd, negate d (ensure P has even y)
     *   2. k = tagged_hash("BIP0340/nonce", d_norm || aux(0) || msg) mod n
     *   3. R = k * G
     *   4. If R.y is odd, negate k
     *   5. e = tagged_hash("BIP0340/challenge", R.x || P.x || msg) mod n
     *   6. s = (k + e * d) mod n
     *   7. return R.x || s
     *
     * @param msg    source buffer containing 32-byte message
     * @param msgOff offset of message in source buffer
     * @param msgLen message length (must be 32)
     * @param out    output buffer (receives 64-byte signature)
     * @param outOff offset in output buffer
     * @return 64 (signature length)
     */
    private short signMessage(byte[] msg, short msgOff, short msgLen,
                              byte[] out, short outOff) {
        try {
            java.math.BigInteger N = new java.math.BigInteger(1, SECP256K1_N);
            java.math.BigInteger Fp = new java.math.BigInteger(1, SECP256K1_P);

            // --- Extract private key scalar d ---
            byte[] dBytes = new byte[32];
            cardPrivKey.getS(dBytes, (short) 0);
            java.math.BigInteger d = new java.math.BigInteger(1, dBytes);

            // --- Extract public key x-coordinate Px ---
            // jCardSim returns uncompressed key (65 bytes: 0x04 || x || y)
            // Real JavaCard hardware returns compressed (33 bytes: 0x02/0x03 || x)
            byte[] wBytes = new byte[65];
            short wLen = cardPubKey.getW(wBytes, (short) 0);

            byte[] Px;
            java.math.BigInteger Py_val;
            if (wLen == 65 && wBytes[0] == 0x04) {
                // Uncompressed (jCardSim)
                Px = java.util.Arrays.copyOfRange(wBytes, 1, 33);
                Py_val = new java.math.BigInteger(1,
                    java.util.Arrays.copyOfRange(wBytes, 33, 65));
            } else {
                // Compressed — derive y from x
                Px = java.util.Arrays.copyOfRange(wBytes, 1, 33);
                java.math.BigInteger x = new java.math.BigInteger(1, Px);
                java.math.BigInteger rhs = x.modPow(java.math.BigInteger.valueOf(3), Fp)
                    .add(java.math.BigInteger.valueOf(7)).mod(Fp);
                Py_val = rhs.modPow(Fp.add(java.math.BigInteger.ONE)
                    .divide(java.math.BigInteger.valueOf(4)), Fp);
                boolean parityBit = (wBytes[0] & 1) == 1;
                if (Py_val.testBit(0) != parityBit) {
                    Py_val = Fp.subtract(Py_val);
                }
            }

            // Step 1: if P.y is odd, negate d
            if (Py_val.testBit(0)) {
                d = N.subtract(d);
            }

            // Step 2: k = tagged_hash("BIP0340/nonce", d_norm || zeros32 || msg) mod n
            byte[] dNorm = toBytes32(d);
            byte[] auxRand = new byte[32]; // deterministic: all zeros
            byte[] msgBytes = java.util.Arrays.copyOfRange(msg, msgOff, msgOff + 32);
            byte[] nonceInput = concat3(dNorm, auxRand, msgBytes);
            byte[] kHash = taggedHash("BIP0340/nonce", nonceInput);
            java.math.BigInteger k = new java.math.BigInteger(1, kHash).mod(N);
            if (k.signum() == 0) k = java.math.BigInteger.ONE; // degenerate case

            // Step 3: R = k * G
            java.math.BigInteger Gx = new java.math.BigInteger(1,
                java.util.Arrays.copyOfRange(SECP256K1_G, 1, 33));
            java.math.BigInteger Gy = new java.math.BigInteger(1,
                java.util.Arrays.copyOfRange(SECP256K1_G, 33, 65));
            java.math.BigInteger[] R = ecMul(k, Gx, Gy, Fp, N);
            if (R == null) ISOException.throwIt(SW_CRYPTO_ERROR);

            // Step 4: if R.y is odd, negate k
            if (R[1].testBit(0)) {
                k = N.subtract(k);
            }
            byte[] Rx = toBytes32(R[0]);

            // Step 5: e = tagged_hash("BIP0340/challenge", Rx || Px || msg) mod n
            byte[] challengeInput = concat3(Rx, Px, msgBytes);
            byte[] eHash = taggedHash("BIP0340/challenge", challengeInput);
            java.math.BigInteger e = new java.math.BigInteger(1, eHash).mod(N);

            // Step 6: s = (k + e * d) mod n
            java.math.BigInteger s = k.add(e.multiply(d)).mod(N);

            // Step 7: sig = Rx || s (64 bytes)
            byte[] sBytes = toBytes32(s);
            System.arraycopy(Rx,     0, out, outOff,        32);
            System.arraycopy(sBytes, 0, out, outOff + 32,   32);
            return (short) 64;

        } catch (ISOException e) {
            throw e;
        } catch (Exception e) {
            ISOException.throwIt(SW_CRYPTO_ERROR);
            return (short) 0; // unreachable
        }
    }

    // -------------------------------------------------------------------------
    // EC math helpers (BigInteger-based, jCardSim/JVM only)
    // -------------------------------------------------------------------------

    /**
     * Scalar multiplication: returns k * (x, y) on the curve y² = x³ + 7 (mod p).
     * Uses double-and-add. Returns null for point at infinity.
     */
    private static java.math.BigInteger[] ecMul(java.math.BigInteger k,
                                                  java.math.BigInteger x,
                                                  java.math.BigInteger y,
                                                  java.math.BigInteger p,
                                                  java.math.BigInteger n) {
        java.math.BigInteger[] R = null;
        java.math.BigInteger[] P = { x, y };
        k = k.mod(n);
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                R = (R == null) ? new java.math.BigInteger[]{ P[0], P[1] }
                                : ecAdd(R[0], R[1], P[0], P[1], p);
            }
            P = ecAdd(P[0], P[1], P[0], P[1], p); // double
            k = k.shiftRight(1);
        }
        return R;
    }

    /**
     * EC point addition / doubling on y² = x³ + 7 (mod p).
     * Handles P == Q (doubling) and P != Q (addition).
     * Returns null for point at infinity.
     */
    private static java.math.BigInteger[] ecAdd(java.math.BigInteger x1,
                                                  java.math.BigInteger y1,
                                                  java.math.BigInteger x2,
                                                  java.math.BigInteger y2,
                                                  java.math.BigInteger p) {
        java.math.BigInteger lambda;
        java.math.BigInteger TWO   = java.math.BigInteger.valueOf(2);
        java.math.BigInteger THREE = java.math.BigInteger.valueOf(3);
        java.math.BigInteger pMinus2 = p.subtract(TWO);

        if (x1.equals(x2)) {
            if (!y1.equals(y2)) return null; // P + (-P) = infinity
            // Doubling: λ = (3x²) / (2y) mod p  [a=0 for secp256k1]
            java.math.BigInteger num = THREE.multiply(x1.modPow(TWO, p)).mod(p);
            java.math.BigInteger den = TWO.multiply(y1).mod(p);
            lambda = num.multiply(den.modPow(pMinus2, p)).mod(p);
        } else {
            // Addition: λ = (y2 - y1) / (x2 - x1) mod p
            java.math.BigInteger num = y2.subtract(y1).mod(p);
            java.math.BigInteger den = x2.subtract(x1).mod(p);
            lambda = num.multiply(den.modPow(pMinus2, p)).mod(p);
        }
        java.math.BigInteger x3 = lambda.modPow(TWO, p).subtract(x1).subtract(x2).mod(p);
        java.math.BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        // Ensure non-negative
        if (x3.signum() < 0) x3 = x3.add(p);
        if (y3.signum() < 0) y3 = y3.add(p);
        return new java.math.BigInteger[]{ x3, y3 };
    }

    /**
     * BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
     */
    private static byte[] taggedHash(String tag, byte[] msg)
            throws java.security.NoSuchAlgorithmException {
        java.security.MessageDigest sha256 =
            java.security.MessageDigest.getInstance("SHA-256");
        byte[] tagHash = sha256.digest(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha256.reset();
        sha256.update(tagHash);
        sha256.update(tagHash);
        sha256.update(msg);
        return sha256.digest();
    }

    /** Encode a BigInteger as a big-endian 32-byte array (zero-padded). */
    private static byte[] toBytes32(java.math.BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        byte[] out = new byte[32];
        if (b.length > 32) {
            // strip leading 0x00 sign byte
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    /** Concatenate three byte arrays. */
    private static byte[] concat3(byte[] a, byte[] b, byte[] c) {
        byte[] out = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, out, 0,                    a.length);
        System.arraycopy(b, 0, out, a.length,             b.length);
        System.arraycopy(c, 0, out, a.length + b.length,  c.length);
        return out;
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
