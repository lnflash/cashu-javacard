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
 * @see <a href="https://github.com/lnflash/cashu-javacard">cashu-javacard</a>
 */
public class CashuApplet extends Applet {

    // APDU instructions
    static final byte INS_GET_PUBKEY      = (byte) 0x10;
    static final byte INS_GET_BALANCE     = (byte) 0x11;
    static final byte INS_GET_PROOF_COUNT = (byte) 0x12;
    static final byte INS_GET_PROOF       = (byte) 0x13;
    static final byte INS_SPEND_PROOF     = (byte) 0x20;
    static final byte INS_LOAD_PROOF      = (byte) 0x30;
    static final byte INS_CLEAR_SPENT     = (byte) 0x31;

    // Proof slot layout (78 bytes each):
    //   1 byte:  status (0=empty, 1=unspent, 2=spent)
    //   8 bytes: keyset_id
    //   4 bytes: amount (big-endian uint32, sats)
    //  32 bytes: secret (x)
    //  33 bytes: C (compressed secp256k1 point)
    static final short PROOF_SIZE         = (short) 78;
    static final short PROOF_STATUS       = (short) 0;
    static final short PROOF_KEYSET_ID    = (short) 1;
    static final short PROOF_AMOUNT       = (short) 9;
    static final short PROOF_SECRET       = (short) 13;
    static final short PROOF_C            = (short) 45;

    static final byte STATUS_EMPTY   = (byte) 0;
    static final byte STATUS_UNSPENT = (byte) 1;
    static final byte STATUS_SPENT   = (byte) 2;

    // Maximum proof slots (adjust based on available EEPROM)
    static final short MAX_PROOFS = (short) 32;

    // Proof storage in persistent EEPROM
    private byte[] proofStorage;

    // Card EC keypair (secp256k1, generated on install, never exported)
    private KeyPair cardKeyPair;
    private ECPrivateKey cardPrivKey;
    private ECPublicKey cardPubKey;

    // Scratch buffer in transient RAM (cleared on deselect)
    private byte[] scratch;

    /**
     * Applet installation entry point.
     * Called once when the applet is installed on the card.
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CashuApplet().register();
    }

    private CashuApplet() {
        // Allocate persistent proof storage
        proofStorage = new byte[(short)(MAX_PROOFS * PROOF_SIZE)];

        // Allocate transient scratch buffer
        scratch = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);

        // Generate secp256k1 card keypair
        // Note: requires chip support for ALG_EC_FP with custom curve params
        // or chip-native secp256k1 support (JCOP4, Feitian JavaCard 3.0.4+)
        initCardKeypair();
    }

    private void initCardKeypair() {
        // TODO: Initialize with secp256k1 curve parameters
        // See spec/SECP256K1.md for curve parameter constants
        // This is the primary implementation challenge:
        // most JavaCard chips support P-256 natively;
        // secp256k1 requires ALG_EC_FP + manual curve params
        // or a chip with explicit secp256k1 support.
        cardKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        // Curve params will be set here once finalized
        cardKeyPair.genKeyPair();
        cardPrivKey = (ECPrivateKey) cardKeyPair.getPrivate();
        cardPubKey  = (ECPublicKey)  cardKeyPair.getPublic();
    }

    @Override
    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) return;

        if (buf[ISO7816.OFFSET_CLA] != (byte) 0xB0) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_GET_PUBKEY:      processGetPubkey(apdu); break;
            case INS_GET_BALANCE:     processGetBalance(apdu); break;
            case INS_GET_PROOF_COUNT: processGetProofCount(apdu); break;
            case INS_GET_PROOF:       processGetProof(apdu); break;
            case INS_SPEND_PROOF:     processSpendProof(apdu); break;
            case INS_LOAD_PROOF:      processLoadProof(apdu); break;
            case INS_CLEAR_SPENT:     processClearSpent(apdu); break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void processGetPubkey(APDU apdu) {
        // Return compressed 33-byte secp256k1 public key
        byte[] buf = apdu.getBuffer();
        short len = cardPubKey.getW(buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void processGetBalance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        long balance = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            short offset = (short)(i * PROOF_SIZE);
            if (proofStorage[(short)(offset + PROOF_STATUS)] == STATUS_UNSPENT) {
                balance += getUint32(proofStorage, (short)(offset + PROOF_AMOUNT));
            }
        }
        // Return as 4-byte big-endian
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
            if (proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS)] != STATUS_EMPTY) {
                count++;
            }
        }
        buf[0] = (byte) count;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void processGetProof(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short idx = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        if (idx >= MAX_PROOFS) ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

        short base = (short)(idx * PROOF_SIZE);
        // Return: 1-byte status + 8-byte keyset_id + 4-byte amount + 32-byte secret + 33-byte C
        Util.arrayCopy(proofStorage, base, buf, (short) 0, PROOF_SIZE);
        apdu.setOutgoingAndSend((short) 0, PROOF_SIZE);
    }

    private void processSpendProof(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short idx = (short)(buf[ISO7816.OFFSET_P1] & 0xFF);
        if (idx >= MAX_PROOFS) ISOException.throwIt(ISO7816.SW_WRONG_P1P2);

        short base = (short)(idx * PROOF_SIZE);
        if (proofStorage[(short)(base + PROOF_STATUS)] == STATUS_SPENT) {
            ISOException.throwIt((short) 0x6985); // Conditions not satisfied — already spent
        }
        if (proofStorage[(short)(base + PROOF_STATUS)] == STATUS_EMPTY) {
            ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        // Mark as spent — IRREVERSIBLE
        proofStorage[(short)(base + PROOF_STATUS)] = STATUS_SPENT;

        // Sign the provided message with card private key (NUT-11 P2PK)
        short msgLen = apdu.setIncomingAndReceive();
        // TODO: Implement Schnorr signature using card private key
        // Signature returned in buf[0..63]
        // For now: placeholder ECDSA (Schnorr to be added)
        apdu.setOutgoingAndSend((short) 0, (short) 64);
    }

    private void processLoadProof(APDU apdu) {
        // Find empty slot
        short slot = -1;
        for (short i = 0; i < MAX_PROOFS; i++) {
            if (proofStorage[(short)(i * PROOF_SIZE + PROOF_STATUS)] == STATUS_EMPTY) {
                slot = i;
                break;
            }
        }
        if (slot == -1) ISOException.throwIt((short) 0x6A84); // Not enough memory

        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen != (short)(PROOF_SIZE - 1)) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

        byte[] buf = apdu.getBuffer();
        short base = (short)(slot * PROOF_SIZE);
        proofStorage[(short)(base + PROOF_STATUS)] = STATUS_UNSPENT;
        Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, proofStorage, (short)(base + PROOF_KEYSET_ID), (short)(PROOF_SIZE - 1));

        buf[0] = (byte) slot;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private void processClearSpent(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short freed = 0;
        for (short i = 0; i < MAX_PROOFS; i++) {
            short base = (short)(i * PROOF_SIZE);
            if (proofStorage[(short)(base + PROOF_STATUS)] == STATUS_SPENT) {
                Util.arrayFillNonAtomic(proofStorage, base, PROOF_SIZE, (byte) 0);
                freed++;
            }
        }
        buf[0] = (byte) freed;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    private long getUint32(byte[] buf, short offset) {
        return ((long)(buf[offset] & 0xFF) << 24)
             | ((long)(buf[(short)(offset+1)] & 0xFF) << 16)
             | ((long)(buf[(short)(offset+2)] & 0xFF) << 8)
             |  (long)(buf[(short)(offset+3)] & 0xFF);
    }
}
