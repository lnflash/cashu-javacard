package me.flashapp.cashu;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.*;

/**
 * jCardSim test suite for CashuApplet.
 *
 * Tests cover all 14 APDU commands across 5 categories:
 *   - Read:     GET_INFO, GET_PUBKEY, GET_BALANCE, GET_PROOF_COUNT, GET_PROOF, GET_SLOT_STATUS
 *   - Spend:    SPEND_PROOF, SIGN_ARBITRARY
 *   - Write:    LOAD_PROOF, CLEAR_SPENT
 *   - Auth:     VERIFY_PIN, SET_PIN, CHANGE_PIN
 *   - Admin:    LOCK_CARD
 *
 * ENG-181 complete: secp256k1 curve params set + BIP-340 Schnorr implemented.
 * Signature tests verify cryptographic correctness using BigInteger Schnorr verify.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CashuAppletTest {

    static final String AID_HEX = "D276000085010200";  // includes trailing class byte for AIDUtil
    static final String AID_STR = "D2760000850102";
    static final byte   CLA     = (byte) 0xB0;

    // Instruction bytes
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

    // Status words
    static final int SW_OK                  = 0x9000;
    static final int SW_WRONG_LENGTH        = 0x6700;
    static final int SW_SECURITY_NOT_SATIS  = 0x6982;
    static final int SW_PIN_BLOCKED         = 0x6983;
    static final int SW_PIN_NOT_SET         = 0x6984;
    static final int SW_CONDITIONS_NOT_SATIS= 0x6985;
    static final int SW_SLOT_OUT_OF_RANGE   = 0x6A83;
    static final int SW_NO_SPACE            = 0x6A84;
    static final int SW_SLOT_EMPTY          = 0x6A88;
    static final int SW_INS_NOT_SUPPORTED   = 0x6D00;
    static final int SW_CLA_NOT_SUPPORTED   = 0x6E00;

    static final int MAX_PROOFS = 32;

    // PIN bytes used across tests
    static final byte[] TEST_PIN     = { 0x31, 0x32, 0x33, 0x34 };  // "1234"
    static final byte[] WRONG_PIN    = { 0x00, 0x00, 0x00, 0x00 };
    static final byte[] NEW_PIN      = { 0x35, 0x36, 0x37, 0x38 };  // "5678"

    // Sample proof data (77 bytes = keyset_id[8] + amount[4] + secret[32] + C[33])
    static final byte[] PROOF_1 = buildProof("0059534c", 1000, 1);
    static final byte[] PROOF_2 = buildProof("008288762774ace1".substring(0,8), 500, 2);

    private CardSimulator simulator;

    @BeforeEach
    void setup() {
        simulator = new CardSimulator();
        AID appletAID = AIDUtil.create(AID_HEX);
        simulator.installApplet(appletAID, CashuApplet.class);
        // SELECT the applet
        CommandAPDU selectApdu = new CommandAPDU(
            0x00, 0xA4, 0x04, 0x00,
            hexToBytes(AID_STR)
        );
        ResponseAPDU resp = simulator.transmitCommand(selectApdu);
        assertEquals(SW_OK, resp.getSW(), "SELECT should succeed");
        assertEquals(2, resp.getData().length, "SELECT should return 2-byte version");
    }

    // =========================================================================
    // SELECT
    // =========================================================================

    @Test @Order(1)
    @DisplayName("SELECT returns version bytes")
    void testSelect() {
        ResponseAPDU resp = transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR)));
        assertEquals(SW_OK, resp.getSW());
        byte[] data = resp.getData();
        assertEquals(2, data.length, "Version response must be 2 bytes");
        assertEquals(0x00, data[0], "Major version = 0");
        assertEquals(0x01, data[1], "Minor version = 1");
    }

    // =========================================================================
    // GET_INFO (0x01)
    // =========================================================================

    @Test @Order(2)
    @DisplayName("GET_INFO returns 8-byte structure with correct initial values")
    void testGetInfo() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256));
        assertEquals(SW_OK, resp.getSW());
        byte[] d = resp.getData();
        assertEquals(8, d.length, "GET_INFO must return 8 bytes");
        assertEquals(0x00, d[0] & 0xFF, "major version");
        assertEquals(0x01, d[1] & 0xFF, "minor version");
        assertEquals(MAX_PROOFS, d[2] & 0xFF, "max slots = 32");
        assertEquals(0, d[3] & 0xFF, "unspent = 0 initially");
        assertEquals(0, d[4] & 0xFF, "spent = 0 initially");
        assertEquals(MAX_PROOFS, d[5] & 0xFF, "empty = 32 initially");
        // bit0 = secp256k1 native, bit1 = Schnorr, bit2 = PIN (all set after ENG-181)
        assertEquals(0x07, d[6] & 0xFF, "Capabilities must be 0x07 (secp256k1+Schnorr+PIN)");
        assertEquals(0, d[7] & 0xFF, "PIN state = 0 (unset) initially");
    }

    // =========================================================================
    // GET_PUBKEY (0x10)
    // =========================================================================

    @Test @Order(3)
    @DisplayName("GET_PUBKEY returns a valid secp256k1 public key (33 or 65 bytes)")
    void testGetPubkey() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256));
        assertEquals(SW_OK, resp.getSW());
        byte[] pub = resp.getData();
        // jCardSim returns uncompressed (65 bytes, 0x04 prefix);
        // real JavaCard hardware returns compressed (33 bytes, 0x02/0x03).
        // Both are valid EC public key encodings.
        assertTrue(pub.length == 33 || pub.length == 65,
            "Public key must be 33 (compressed) or 65 (uncompressed) bytes, got: " + pub.length);
        if (pub.length == 33) {
            assertTrue(pub[0] == 0x02 || pub[0] == 0x03, "Compressed key prefix must be 0x02 or 0x03");
        } else {
            assertEquals(0x04, pub[0] & 0xFF, "Uncompressed key prefix must be 0x04");
        }
    }

    @Test @Order(4)
    @DisplayName("GET_PUBKEY is stable (same key across multiple calls)")
    void testGetPubkeyStable() {
        byte[] pub1 = transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData();
        byte[] pub2 = transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData();
        assertArrayEquals(pub1, pub2, "Public key must be stable");
    }

    // =========================================================================
    // GET_BALANCE (0x11)
    // =========================================================================

    @Test @Order(5)
    @DisplayName("GET_BALANCE returns 0 on fresh card")
    void testGetBalanceEmpty() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4));
        assertEquals(SW_OK, resp.getSW());
        byte[] d = resp.getData();
        assertEquals(4, d.length);
        assertEquals(0L, readUint32(d, 0), "Balance must be 0 on fresh card");
    }

    // =========================================================================
    // GET_PROOF_COUNT (0x12)
    // =========================================================================

    @Test @Order(6)
    @DisplayName("GET_PROOF_COUNT returns 0 on fresh card")
    void testGetProofCountEmpty() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(0, resp.getData()[0] & 0xFF);
    }

    // =========================================================================
    // GET_SLOT_STATUS (0x14)
    // =========================================================================

    @Test @Order(7)
    @DisplayName("GET_SLOT_STATUS returns 32 zero bytes on fresh card")
    void testGetSlotStatusEmpty() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, MAX_PROOFS));
        assertEquals(SW_OK, resp.getSW());
        byte[] statuses = resp.getData();
        assertEquals(MAX_PROOFS, statuses.length);
        for (int i = 0; i < MAX_PROOFS; i++) {
            assertEquals(0, statuses[i] & 0xFF, "Slot " + i + " should be empty");
        }
    }

    // =========================================================================
    // GET_PROOF (0x13) — error cases before any proofs loaded
    // =========================================================================

    @Test @Order(8)
    @DisplayName("GET_PROOF on empty slot returns SW_SLOT_EMPTY")
    void testGetProofSlotEmpty() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 78));
        assertEquals(SW_SLOT_EMPTY, resp.getSW());
    }

    @Test @Order(9)
    @DisplayName("GET_PROOF with out-of-range index returns SW_SLOT_OUT_OF_RANGE")
    void testGetProofOutOfRange() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_PROOF, MAX_PROOFS, 0, 78));
        assertEquals(SW_SLOT_OUT_OF_RANGE, resp.getSW());
    }

    // =========================================================================
    // LOAD_PROOF (0x30) — no PIN set
    // =========================================================================

    @Test @Order(10)
    @DisplayName("LOAD_PROOF succeeds without PIN when PIN is not set")
    void testLoadProofNoPinRequired() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        assertEquals(SW_OK, resp.getSW());
        byte slotIdx = resp.getData()[0];
        assertEquals(0, slotIdx & 0xFF, "First proof should be in slot 0");
    }

    @Test @Order(11)
    @DisplayName("LOAD_PROOF wrong data length returns SW_WRONG_LENGTH")
    void testLoadProofWrongLength() {
        byte[] shortProof = new byte[10];
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, shortProof, 0, shortProof.length, 1));
        assertEquals(SW_WRONG_LENGTH, resp.getSW());
    }

    @Test @Order(12)
    @DisplayName("LOAD_PROOF fills slots sequentially")
    void testLoadProofSequential() {
        for (int i = 0; i < 3; i++) {
            byte[] proof = buildProof("0059534c", 100 * (i + 1), i + 1);
            ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, proof, 0, proof.length, 1));
            assertEquals(SW_OK, resp.getSW());
            assertEquals(i, resp.getData()[0] & 0xFF, "Slot index should be " + i);
        }
    }

    // =========================================================================
    // GET_PROOF (0x13) — after loading
    // =========================================================================

    @Test @Order(13)
    @DisplayName("GET_PROOF returns correct data after LOAD_PROOF")
    void testGetProofAfterLoad() {
        // Load proof into slot 0
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 78));
        assertEquals(SW_OK, resp.getSW());
        byte[] data = resp.getData();
        assertEquals(78, data.length, "Proof data must be 78 bytes");
        assertEquals(0x01, data[0] & 0xFF, "Status must be UNSPENT (0x01)");

        // Verify the proof payload matches what we loaded (bytes 1..77)
        for (int i = 0; i < 77; i++) {
            assertEquals(PROOF_1[i] & 0xFF, data[i + 1] & 0xFF,
                "Proof byte " + i + " mismatch");
        }
    }

    // =========================================================================
    // GET_BALANCE — after loading
    // =========================================================================

    @Test @Order(14)
    @DisplayName("GET_BALANCE reflects loaded proof amounts")
    void testGetBalanceAfterLoad() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1)); // 1000
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_2, 0, PROOF_2.length, 1)); // 500

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(1500L, readUint32(resp.getData(), 0), "Balance should be 1000 + 500 = 1500");
    }

    // =========================================================================
    // GET_PROOF_COUNT — after loading
    // =========================================================================

    @Test @Order(15)
    @DisplayName("GET_PROOF_COUNT increments after LOAD_PROOF")
    void testGetProofCountAfterLoad() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_2, 0, PROOF_2.length, 1));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_PROOF_COUNT, 0, 0, 1));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(2, resp.getData()[0] & 0xFF);
    }

    // =========================================================================
    // GET_SLOT_STATUS — after loading
    // =========================================================================

    @Test @Order(16)
    @DisplayName("GET_SLOT_STATUS shows correct status after LOAD_PROOF")
    void testGetSlotStatusAfterLoad() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, MAX_PROOFS));
        assertEquals(SW_OK, resp.getSW());
        byte[] statuses = resp.getData();
        assertEquals(0x01, statuses[0] & 0xFF, "Slot 0 should be UNSPENT");
        for (int i = 1; i < MAX_PROOFS; i++) {
            assertEquals(0x00, statuses[i] & 0xFF, "Slot " + i + " should be EMPTY");
        }
    }

    // =========================================================================
    // SPEND_PROOF (0x20)
    // =========================================================================

    @Test @Order(17)
    @DisplayName("SPEND_PROOF returns 64-byte signature and marks slot spent")
    void testSpendProof() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));

        byte[] msg = new byte[32];
        for (int i = 0; i < 32; i++) msg[i] = (byte) i; // dummy message

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, msg, 0, 32, 64));
        assertEquals(SW_OK, resp.getSW());
        byte[] sig = resp.getData();
        assertEquals(64, sig.length, "Signature must be 64 bytes");
        assertFalse(isAllZeros(sig), "Signature must not be all zeros (stub check)");

        // Verify slot is now SPENT
        ResponseAPDU proofResp = transmit(new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 78));
        assertEquals(SW_OK, proofResp.getSW());
        assertEquals(0x02, proofResp.getData()[0] & 0xFF, "Status must be SPENT after spend");
    }

    @Test @Order(18)
    @DisplayName("SPEND_PROOF on spent slot returns SW_ALREADY_SPENT (6985)")
    void testSpendProofDoubleSpend() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        byte[] msg = new byte[32];

        // First spend
        transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, msg, 0, 32, 64));

        // Second spend — should fail
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, msg, 0, 32, 64));
        assertEquals(SW_CONDITIONS_NOT_SATIS, resp.getSW(), "Double spend must be rejected");
    }

    @Test @Order(19)
    @DisplayName("SPEND_PROOF on empty slot returns SW_SLOT_EMPTY")
    void testSpendProofEmptySlot() {
        byte[] msg = new byte[32];
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, msg, 0, 32, 64));
        assertEquals(SW_SLOT_EMPTY, resp.getSW());
    }

    @Test @Order(20)
    @DisplayName("SPEND_PROOF with wrong message length returns SW_WRONG_LENGTH")
    void testSpendProofWrongMsgLength() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        byte[] shortMsg = new byte[16];
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, shortMsg, 0, shortMsg.length, 64));
        assertEquals(SW_WRONG_LENGTH, resp.getSW());
    }

    @Test @Order(21)
    @DisplayName("GET_BALANCE decreases to zero after all proofs spent")
    void testBalanceAfterSpend() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        byte[] msg = new byte[32];
        transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, msg, 0, 32, 64));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(0L, readUint32(resp.getData(), 0), "Balance must be 0 after spending all proofs");
    }

    // =========================================================================
    // SIGN_ARBITRARY (0x21)
    // =========================================================================

    @Test @Order(22)
    @DisplayName("SIGN_ARBITRARY returns 64-byte signature without affecting proofs")
    void testSignArbitrary() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        long balanceBefore = readUint32(
            transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)).getData(), 0);

        byte[] msg = new byte[32];
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg, 0, 32, 64));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(64, resp.getData().length);

        // Balance unchanged
        long balanceAfter = readUint32(
            transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)).getData(), 0);
        assertEquals(balanceBefore, balanceAfter, "SIGN_ARBITRARY must not consume proofs");
    }

    @Test @Order(23)
    @DisplayName("SIGN_ARBITRARY wrong message length returns SW_WRONG_LENGTH")
    void testSignArbitraryWrongLength() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, new byte[16], 0, 16, 64));
        assertEquals(SW_WRONG_LENGTH, resp.getSW());
    }

    // =========================================================================
    // Schnorr signature cryptographic verification (ENG-181)
    // =========================================================================

    @Test @Order(24)
    @DisplayName("SIGN_ARBITRARY produces a valid BIP-340 Schnorr signature")
    void testSignArbitrarySchnorrValid() throws Exception {
        // Get card public key
        byte[] pubBytes = transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData();

        // Sign a known 32-byte message
        byte[] msg = new byte[32];
        for (int i = 0; i < 32; i++) msg[i] = (byte)(i + 1);

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg, 0, 32, 64));
        assertEquals(SW_OK, resp.getSW());
        byte[] sig = resp.getData();
        assertEquals(64, sig.length);
        assertFalse(isAllZeros(sig), "Signature must not be all zeros");

        // Extract 32-byte x-coordinate of public key
        byte[] pubX = extractPubkeyX(pubBytes);

        // Verify BIP-340 Schnorr signature
        assertTrue(schnorrVerify(pubX, msg, sig),
            "Schnorr signature must verify against the card's public key");
    }

    @Test @Order(25)
    @DisplayName("SPEND_PROOF produces a valid BIP-340 Schnorr signature")
    void testSpendProofSchnorrValid() throws Exception {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));

        byte[] pubBytes = transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData();
        byte[] pubX = extractPubkeyX(pubBytes);

        byte[] msg = new byte[32];
        for (int i = 0; i < 32; i++) msg[i] = (byte)(0xAB ^ i);

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, msg, 0, 32, 64));
        assertEquals(SW_OK, resp.getSW());
        byte[] sig = resp.getData();

        assertTrue(schnorrVerify(pubX, msg, sig),
            "SPEND_PROOF Schnorr signature must verify");
    }

    @Test @Order(26)
    @DisplayName("Different messages produce different signatures (non-determinism test)")
    void testSignArbitraryDifferentMessages() throws Exception {
        byte[] msg1 = new byte[32];
        byte[] msg2 = new byte[32];
        java.util.Arrays.fill(msg1, (byte) 0x01);
        java.util.Arrays.fill(msg2, (byte) 0x02);

        // Need two proofs since SPEND_PROOF marks slots spent
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_2, 0, PROOF_2.length, 1));

        byte[] sig1 = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg1, 0, 32, 64)).getData();
        byte[] sig2 = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg2, 0, 32, 64)).getData();

        assertFalse(java.util.Arrays.equals(sig1, sig2),
            "Different messages must produce different signatures");
    }

    @Test @Order(27)
    @DisplayName("Signature for wrong message does not verify")
    void testSignArbitraryWrongMsgDoesNotVerify() throws Exception {
        byte[] pubBytes = transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData();
        byte[] pubX = extractPubkeyX(pubBytes);

        byte[] msg = new byte[32];
        java.util.Arrays.fill(msg, (byte) 0x42);

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg, 0, 32, 64));
        byte[] sig = resp.getData();

        byte[] wrongMsg = new byte[32];
        java.util.Arrays.fill(wrongMsg, (byte) 0x99);

        assertFalse(schnorrVerify(pubX, wrongMsg, sig),
            "Signature must not verify against a different message");
    }

    // =========================================================================
    // CLEAR_SPENT (0x31)
    // =========================================================================

    @Test @Order(24)
    @DisplayName("CLEAR_SPENT frees spent slots and returns freed count")
    void testClearSpent() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_2, 0, PROOF_2.length, 1));

        // Spend slot 0
        transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, new byte[32], 0, 32, 64));

        ResponseAPDU clearResp = transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1));
        assertEquals(SW_OK, clearResp.getSW());
        assertEquals(1, clearResp.getData()[0] & 0xFF, "Should free 1 spent slot");

        // Slot 0 should now be EMPTY, slot 1 still UNSPENT
        byte[] statuses = transmit(new CommandAPDU(CLA, INS_GET_SLOT_STATUS, 0, 0, MAX_PROOFS)).getData();
        assertEquals(0x00, statuses[0] & 0xFF, "Slot 0 should be EMPTY after CLEAR_SPENT");
        assertEquals(0x01, statuses[1] & 0xFF, "Slot 1 should still be UNSPENT");
    }

    @Test @Order(25)
    @DisplayName("CLEAR_SPENT returns 0 when no spent proofs exist")
    void testClearSpentNoneToFree() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(0, resp.getData()[0] & 0xFF, "No spent proofs to free");
    }

    @Test @Order(26)
    @DisplayName("LOAD_PROOF NO_SPACE after all 32 slots filled")
    void testLoadProofNoSpace() {
        for (int i = 0; i < MAX_PROOFS; i++) {
            byte[] proof = buildProof("0059534c", 1, i);
            ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, proof, 0, proof.length, 1));
            assertEquals(SW_OK, resp.getSW(), "Slot " + i + " should be loadable");
        }
        byte[] overflow = buildProof("0059534c", 1, 99);
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, overflow, 0, overflow.length, 1));
        assertEquals(SW_NO_SPACE, resp.getSW(), "33rd proof should fail with NO_SPACE");
    }

    // =========================================================================
    // PIN — SET_PIN (0x41)
    // =========================================================================

    @Test @Order(27)
    @DisplayName("SET_PIN succeeds on fresh card")
    void testSetPin() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        assertEquals(SW_OK, resp.getSW());

        // GET_INFO should now show PIN state = 1 (set)
        byte[] info = transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData();
        assertEquals(1, info[7] & 0xFF, "PIN state should be 1 (set) after SET_PIN");
    }

    @Test @Order(28)
    @DisplayName("SET_PIN a second time returns SW_CONDITIONS_NOT_SATIS")
    void testSetPinAlreadySet() {
        transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN, 0, NEW_PIN.length));
        assertEquals(SW_CONDITIONS_NOT_SATIS, resp.getSW());
    }

    // =========================================================================
    // PIN — VERIFY_PIN (0x40)
    // =========================================================================

    @Test @Order(29)
    @DisplayName("VERIFY_PIN succeeds with correct PIN")
    void testVerifyPinCorrect() {
        transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        assertEquals(SW_OK, resp.getSW());
    }

    @Test @Order(30)
    @DisplayName("VERIFY_PIN with wrong PIN returns 63CX with decrementing counter")
    void testVerifyPinWrong() {
        transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN, 0, WRONG_PIN.length));
        int sw = resp.getSW();
        assertEquals(0x63C0, sw & 0xFFF0, "Wrong PIN SW must be 0x63CX");
        assertTrue((sw & 0x0F) < 3, "Retry counter should have decremented");
    }

    @Test @Order(31)
    @DisplayName("VERIFY_PIN blocks after max retries exhausted")
    void testVerifyPinBlocked() {
        transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));

        // Exhaust retries (default 3)
        for (int i = 0; i < 3; i++) {
            transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN, 0, WRONG_PIN.length));
        }

        // Now PIN should be blocked
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        assertEquals(SW_PIN_BLOCKED, resp.getSW(), "PIN must be blocked after max retries");

        // GET_INFO PIN state should show 2 (locked)
        byte[] info = transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData();
        assertEquals(2, info[7] & 0xFF, "PIN state should be 2 (locked)");
    }

    @Test @Order(32)
    @DisplayName("VERIFY_PIN on card with no PIN set returns SW_PIN_NOT_SET")
    void testVerifyPinNotSet() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        assertEquals(SW_PIN_NOT_SET, resp.getSW());
    }

    // =========================================================================
    // PIN gate on LOAD_PROOF
    // =========================================================================

    @Test @Order(33)
    @DisplayName("LOAD_PROOF is blocked when PIN is set but not verified")
    void testLoadProofPinRequired() {
        transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        assertEquals(SW_SECURITY_NOT_SATIS, resp.getSW(), "LOAD_PROOF must require PIN when PIN is set");
    }

    @Test @Order(34)
    @DisplayName("LOAD_PROOF succeeds after VERIFY_PIN")
    void testLoadProofAfterPinVerified() {
        transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        assertEquals(SW_OK, resp.getSW());
    }

    // =========================================================================
    // CHANGE_PIN (0x42)
    // =========================================================================

    @Test @Order(35)
    @DisplayName("CHANGE_PIN succeeds and new PIN works")
    void testChangePin() {
        transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));

        // Data: 1-byte old-pin-len + old-pin + new-pin
        byte[] changePinData = new byte[1 + TEST_PIN.length + NEW_PIN.length];
        changePinData[0] = (byte) TEST_PIN.length;
        System.arraycopy(TEST_PIN, 0, changePinData, 1, TEST_PIN.length);
        System.arraycopy(NEW_PIN, 0, changePinData, 1 + TEST_PIN.length, NEW_PIN.length);

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_CHANGE_PIN, 0, 0, changePinData));
        assertEquals(SW_OK, resp.getSW());

        // Old PIN should no longer work
        ResponseAPDU oldPinResp = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length));
        assertNotEquals(SW_OK, oldPinResp.getSW(), "Old PIN should be rejected after change");

        // New PIN should work
        ResponseAPDU newPinResp = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, NEW_PIN, 0, NEW_PIN.length));
        assertEquals(SW_OK, newPinResp.getSW());
    }

    // =========================================================================
    // LOCK_CARD (0x50)
    // =========================================================================

    @Test @Order(36)
    @DisplayName("LOCK_CARD blocks LOAD_PROOF permanently")
    void testLockCard() {
        // Lock with confirmation byte P2=0xDE
        ResponseAPDU lockResp = transmit(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE));
        assertEquals(SW_OK, lockResp.getSW());

        // LOAD_PROOF should now fail
        ResponseAPDU loadResp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, loadResp.getSW(), "LOAD_PROOF must be blocked on locked card");
    }

    @Test @Order(37)
    @DisplayName("LOCK_CARD without confirmation byte is rejected")
    void testLockCardNoConfirm() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0x00));
        assertNotEquals(SW_OK, resp.getSW(), "LOCK_CARD without P2=0xDE must fail");
    }

    @Test @Order(38)
    @DisplayName("SPEND_PROOF still works on locked card (bearer spend is always allowed)")
    void testSpendProofOnLockedCard() {
        transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
        transmit(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE));

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, new byte[32], 0, 32, 64));
        assertEquals(SW_OK, resp.getSW(), "Spending must be allowed even on locked card");
    }

    // =========================================================================
    // CLA / INS validation
    // =========================================================================

    @Test @Order(39)
    @DisplayName("Unsupported CLA returns SW_CLA_NOT_SUPPORTED")
    void testUnsupportedCla() {
        ResponseAPDU resp = transmit(new CommandAPDU(0x00, INS_GET_PUBKEY, 0, 0, 256));
        assertEquals(SW_CLA_NOT_SUPPORTED, resp.getSW());
    }

    @Test @Order(40)
    @DisplayName("Unknown INS returns SW_INS_NOT_SUPPORTED")
    void testUnknownIns() {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, 0xFF, 0, 0, 256));
        assertEquals(SW_INS_NOT_SUPPORTED, resp.getSW());
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private ResponseAPDU transmit(CommandAPDU apdu) {
        return simulator.transmitCommand(apdu);
    }

    /** Build a 77-byte proof payload: keyset_id[8] + amount[4] + secret[32] + C[33] */
    static byte[] buildProof(String keysetIdHex, long amount, int seed) {
        byte[] proof = new byte[77];
        // keyset_id: 8 bytes from hex string (padded)
        byte[] kid = hexToBytes(keysetIdHex.length() >= 16
            ? keysetIdHex.substring(0, 16)
            : String.format("%-16s", keysetIdHex).replace(' ', '0'));
        System.arraycopy(kid, 0, proof, 0, 8);
        // amount: big-endian uint32
        proof[8]  = (byte)((amount >> 24) & 0xFF);
        proof[9]  = (byte)((amount >> 16) & 0xFF);
        proof[10] = (byte)((amount >> 8)  & 0xFF);
        proof[11] = (byte)( amount        & 0xFF);
        // secret: 32 bytes filled with seed value
        for (int i = 0; i < 32; i++) proof[12 + i] = (byte) seed;
        // C point: 33 bytes (02 prefix + 32 bytes of seed+1)
        proof[44] = 0x02;
        for (int i = 0; i < 32; i++) proof[45 + i] = (byte)(seed + 1);
        return proof;
    }

    static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }

    static long readUint32(byte[] buf, int offset) {
        return ((long)(buf[offset]     & 0xFF) << 24)
             | ((long)(buf[offset + 1] & 0xFF) << 16)
             | ((long)(buf[offset + 2] & 0xFF) << 8)
             |  (long)(buf[offset + 3] & 0xFF);
    }

    // =========================================================================
    // Schnorr / EC helpers (BigInteger, jCardSim/JVM only)
    // =========================================================================

    static final java.math.BigInteger SECP_P = new java.math.BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    static final java.math.BigInteger SECP_N = new java.math.BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    static final java.math.BigInteger SECP_GX = new java.math.BigInteger(
        "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    static final java.math.BigInteger SECP_GY = new java.math.BigInteger(
        "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);

    /**
     * BIP-340 Schnorr verify.
     * sig = R.x (32) || s (32)
     */
    static boolean schnorrVerify(byte[] pubX, byte[] msg, byte[] sig)
            throws java.security.NoSuchAlgorithmException {
        java.math.BigInteger p = SECP_P;
        java.math.BigInteger n = SECP_N;

        java.math.BigInteger r = new java.math.BigInteger(1,
            java.util.Arrays.copyOfRange(sig, 0, 32));
        java.math.BigInteger s = new java.math.BigInteger(1,
            java.util.Arrays.copyOfRange(sig, 32, 64));

        if (r.compareTo(p) >= 0) return false;
        if (s.compareTo(n) >= 0) return false;

        // P = lift_x(pubX) — even-y point
        java.math.BigInteger[] P = liftX(new java.math.BigInteger(1, pubX));
        if (P == null) return false;

        // e = tagged_hash("BIP0340/challenge", bytes(r) || bytes(P.x) || msg) mod n
        byte[] rBytes  = toBytes32Test(r);
        byte[] PxBytes = toBytes32Test(P[0]);
        byte[] challengeInput = new byte[96];
        System.arraycopy(rBytes,  0, challengeInput,  0, 32);
        System.arraycopy(PxBytes, 0, challengeInput, 32, 32);
        System.arraycopy(msg,     0, challengeInput, 64, 32);
        java.math.BigInteger e = new java.math.BigInteger(1,
            taggedHashTest("BIP0340/challenge", challengeInput)).mod(n);

        // R = s*G - e*P  (subtract = add negated point: -P = (P.x, p - P.y))
        java.math.BigInteger[] sG  = ecMulTest(s,  SECP_GX, SECP_GY);
        java.math.BigInteger[] eP  = ecMulTest(e,  P[0],    P[1]);
        if (sG == null || eP == null) return false;

        // Negate eP: (eP.x, p - eP.y)
        java.math.BigInteger[] negEP = { eP[0], p.subtract(eP[1]) };
        java.math.BigInteger[] R = ecAddTest(sG[0], sG[1], negEP[0], negEP[1]);
        if (R == null) return false;

        // R.y must be even, R.x must equal r
        if (R[1].testBit(0)) return false;
        return R[0].equals(r);
    }

    /** lift_x: find the even-y point on secp256k1 with the given x-coordinate. */
    static java.math.BigInteger[] liftX(java.math.BigInteger x) {
        java.math.BigInteger p = SECP_P;
        if (x.compareTo(p) >= 0) return null;
        java.math.BigInteger rhs = x.modPow(java.math.BigInteger.valueOf(3), p)
            .add(java.math.BigInteger.valueOf(7)).mod(p);
        java.math.BigInteger y = rhs.modPow(p.add(java.math.BigInteger.ONE)
            .divide(java.math.BigInteger.valueOf(4)), p);
        // Verify it's actually a square root
        if (!y.modPow(java.math.BigInteger.TWO, p).equals(rhs)) return null;
        // Choose even y
        if (y.testBit(0)) y = p.subtract(y);
        return new java.math.BigInteger[]{ x, y };
    }

    /** Extract 32-byte x-coordinate from a compressed (33) or uncompressed (65) public key. */
    static byte[] extractPubkeyX(byte[] pubBytes) {
        if (pubBytes.length == 65 && pubBytes[0] == 0x04) {
            return java.util.Arrays.copyOfRange(pubBytes, 1, 33);
        } else if (pubBytes.length == 33) {
            return java.util.Arrays.copyOfRange(pubBytes, 1, 33);
        }
        throw new IllegalArgumentException("Unexpected pubkey length: " + pubBytes.length);
    }

    /** Returns true if every byte in the array is 0x00. */
    static boolean isAllZeros(byte[] b) {
        for (byte v : b) if (v != 0) return false;
        return true;
    }

    /** Scalar multiplication: k * (x,y) using double-and-add. */
    static java.math.BigInteger[] ecMulTest(java.math.BigInteger k,
                                             java.math.BigInteger x,
                                             java.math.BigInteger y) {
        java.math.BigInteger[] R = null;
        java.math.BigInteger[] P = { x, y };
        k = k.mod(SECP_N);
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                R = (R == null) ? new java.math.BigInteger[]{ P[0], P[1] }
                                : ecAddTest(R[0], R[1], P[0], P[1]);
            }
            P = ecAddTest(P[0], P[1], P[0], P[1]);
            k = k.shiftRight(1);
        }
        return R;
    }

    /** EC point addition / doubling on secp256k1. Returns null for point at infinity. */
    static java.math.BigInteger[] ecAddTest(java.math.BigInteger x1,
                                             java.math.BigInteger y1,
                                             java.math.BigInteger x2,
                                             java.math.BigInteger y2) {
        java.math.BigInteger p  = SECP_P;
        java.math.BigInteger p2 = p.subtract(java.math.BigInteger.TWO);
        java.math.BigInteger lambda;
        if (x1.equals(x2)) {
            if (!y1.equals(y2)) return null; // point at infinity
            // doubling
            java.math.BigInteger num = java.math.BigInteger.valueOf(3)
                .multiply(x1.modPow(java.math.BigInteger.TWO, p)).mod(p);
            java.math.BigInteger den = java.math.BigInteger.valueOf(2).multiply(y1).mod(p);
            lambda = num.multiply(den.modPow(p2, p)).mod(p);
        } else {
            java.math.BigInteger num = y2.subtract(y1).mod(p);
            java.math.BigInteger den = x2.subtract(x1).mod(p);
            lambda = num.multiply(den.modPow(p2, p)).mod(p);
        }
        java.math.BigInteger x3 = lambda.modPow(java.math.BigInteger.TWO, p)
            .subtract(x1).subtract(x2).mod(p);
        java.math.BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        if (x3.signum() < 0) x3 = x3.add(p);
        if (y3.signum() < 0) y3 = y3.add(p);
        return new java.math.BigInteger[]{ x3, y3 };
    }

    /** BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg) */
    static byte[] taggedHashTest(String tag, byte[] msg)
            throws java.security.NoSuchAlgorithmException {
        java.security.MessageDigest sha =
            java.security.MessageDigest.getInstance("SHA-256");
        byte[] tagHash = sha.digest(
            tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sha.reset();
        sha.update(tagHash);
        sha.update(tagHash);
        sha.update(msg);
        return sha.digest();
    }

    /** BigInteger → big-endian 32-byte array (zero-padded / sign-stripped). */
    static byte[] toBytes32Test(java.math.BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        byte[] out = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, out, 0, 32);
        } else {
            System.arraycopy(b, 0, out, 32 - b.length, b.length);
        }
        return out;
    }

    // Expose ISO7816 constants for tests
    static class ISO7816 {
        static final int SW_COMMAND_NOT_ALLOWED = 0x6986;
    }
}
