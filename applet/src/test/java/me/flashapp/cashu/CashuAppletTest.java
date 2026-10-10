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
 * Tests cover all 15 APDU commands across 5 categories:
 *   - Read:     GET_INFO, GET_PUBKEY, GET_BALANCE, GET_PROOF_COUNT, GET_PROOF, GET_SLOT_STATUS
 *   - Spend:    SPEND_PROOF, SIGN_ARBITRARY
 *   - Write:    LOAD_PROOF, CLEAR_SPENT
 *   - Auth:     VERIFY_PIN, SET_PIN, CHANGE_PIN, CLEAR_PIN
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
    static final byte INS_CLEAR_PIN        = (byte) 0x43;
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

    // Sample proof data (77 bytes = keyset_id[8] + amount[4] + nonce[32] + C[33]).
    // Full 16-hex-char NUT-02 keyset ids, as a real mint issues them.
    static final byte[] PROOF_1 = buildProof("0059534ce0bfa19a", 1000, 1);
    static final byte[] PROOF_2 = buildProof("008288762774ace1", 500, 2);

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
        assertEquals(0x05, data[1],
            "Minor version = 5 (CLEAR_PIN, D15). A card that answers 0x43 must not answer "
                + "SELECT like a 0.4 build, which answers it 6D00; nor like the 0.3 build main "
                + "tracked with the old write order (ENG-620), nor the ENG-615 builds below it.");
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
        assertEquals(0x05, d[1] & 0xFF, "minor version");
        assertEquals(MAX_PROOFS, d[2] & 0xFF, "max slots = 32");
        assertEquals(0, d[3] & 0xFF, "unspent = 0 initially");
        assertEquals(0, d[4] & 0xFF, "spent = 0 initially");
        assertEquals(MAX_PROOFS, d[5] & 0xFF, "empty = 32 initially");
        // bit0 = secp256k1 native, bit1 = Schnorr, bit2 = PIN (all set after ENG-181),
        // bit3 = CLEAR_PIN (applet 0.5, D15)
        assertEquals(0x0F, d[6] & 0xFF, "Capabilities must be 0x0F (secp256k1+Schnorr+PIN+CLEAR_PIN)");
        assertEquals(0, d[7] & 0xFF, "PIN state = 0 (unset) initially");
    }

    // =========================================================================
    // GET_PUBKEY (0x10)
    // =========================================================================

    @Test @Order(3)
    @DisplayName("GET_PUBKEY returns a 33-byte compressed secp256k1 public key")
    void testGetPubkey() throws Exception {
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256));
        assertEquals(SW_OK, resp.getSW());
        byte[] pub = resp.getData();
        // The wire format is fixed at 33 bytes (spec/APDU.md) even though
        // ECPublicKey.getW() hands back the uncompressed point on hardware.
        assertEquals(33, pub.length, "Public key must be 33-byte compressed");
        assertTrue(pub[0] == 0x02 || pub[0] == 0x03,
            "Compressed key prefix must be 0x02 or 0x03");
        assertNotNull(liftX(new java.math.BigInteger(1,
            java.util.Arrays.copyOfRange(pub, 1, 33))), "Public key must be on secp256k1");

        // The compressed key must be the very key the card signs with: verify a
        // real signature against its x-only form.
        byte[] msg = new byte[32];
        for (int i = 0; i < 32; i++) msg[i] = (byte) (i + 1);
        ResponseAPDU signed = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg, 0, 32, 64));
        assertEquals(SW_OK, signed.getSW());
        assertTrue(schnorrVerify(java.util.Arrays.copyOfRange(pub, 1, 33), msg, signed.getData()),
            "Signature must verify against the key GET_PUBKEY returned");
    }

    // No @Order: a pure static helper with no card state, so it runs after the
    // ordered APDU sequence rather than displacing its numbering.
    @Test
    @DisplayName("toCompressed normalises the 65-byte hardware point to 33 bytes")
    void testToCompressed() {
        // jCardSim's getW() already returns 33 bytes, so the branch that runs on
        // real silicon is invisible here unless driven directly.
        byte[] gx = toBytes32Test(SECP_GX);
        byte[] gy = toBytes32Test(SECP_GY);
        byte[] gyOdd = toBytes32Test(SECP_P.subtract(SECP_GY));

        byte[] even = new byte[65];
        even[0] = 0x04;
        System.arraycopy(gx, 0, even, 1, 32);
        System.arraycopy(gy, 0, even, 33, 32);
        assertEquals(33, CashuApplet.toCompressed(even, (short) 65));
        assertEquals(0x02, even[0] & 0xFF, "even Y must yield a 0x02 prefix");
        assertArrayEquals(gx, java.util.Arrays.copyOfRange(even, 1, 33), "X must be preserved");

        byte[] odd = new byte[65];
        odd[0] = 0x04;
        System.arraycopy(gx, 0, odd, 1, 32);
        System.arraycopy(gyOdd, 0, odd, 33, 32);
        assertEquals(33, CashuApplet.toCompressed(odd, (short) 65));
        assertEquals(0x03, odd[0] & 0xFF, "odd Y must yield a 0x03 prefix");

        byte[] compressed = new byte[33];
        compressed[0] = 0x02;
        System.arraycopy(gx, 0, compressed, 1, 32);
        assertEquals(33, CashuApplet.toCompressed(compressed, (short) 33));
        assertArrayEquals(gx, java.util.Arrays.copyOfRange(compressed, 1, 33),
            "an already-compressed key must pass through untouched");
    }

    @Test
    @DisplayName("toCompressed refuses encodings it does not recognise")
    void testToCompressedRejectsUnknownEncodings() {
        // Same policy as SchnorrHW.sign() for the same getW() output: an
        // encoding we cannot name must not reach the host as a "pubkey".
        byte[] gx = toBytes32Test(SECP_GX);
        byte[] gy = toBytes32Test(SECP_GY);

        // 65 bytes without the 0x04 marker.
        byte[] badMarker = new byte[65];
        badMarker[0] = 0x05;
        System.arraycopy(gx, 0, badMarker, 1, 32);
        System.arraycopy(gy, 0, badMarker, 33, 32);
        assertCryptoError(() -> CashuApplet.toCompressed(badMarker, (short) 65));

        // A bare X || Y with no marker at all.
        byte[] bare = new byte[64];
        System.arraycopy(gx, 0, bare, 0, 32);
        System.arraycopy(gy, 0, bare, 32, 32);
        assertCryptoError(() -> CashuApplet.toCompressed(bare, (short) 64));

        // 33 bytes with a prefix that is not 02/03.
        byte[] badPrefix = new byte[33];
        badPrefix[0] = 0x04;
        System.arraycopy(gx, 0, badPrefix, 1, 32);
        assertCryptoError(() -> CashuApplet.toCompressed(badPrefix, (short) 33));

        // Wrong length outright.
        assertCryptoError(() -> CashuApplet.toCompressed(new byte[32], (short) 32));
    }

    private static void assertCryptoError(org.junit.jupiter.api.function.Executable call) {
        javacard.framework.ISOException thrown =
            assertThrows(javacard.framework.ISOException.class, call);
        assertEquals(CashuApplet.SW_CRYPTO_ERROR, thrown.getReason(),
            "unrecognised encoding must fail with SW_CRYPTO_ERROR");
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
            byte[] proof = buildProof("0059534ce0bfa19a", 100 * (i + 1), i + 1);
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
            byte[] proof = buildProof("0059534ce0bfa19a", 1, i);
            ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, proof, 0, proof.length, 1));
            assertEquals(SW_OK, resp.getSW(), "Slot " + i + " should be loadable");
        }
        byte[] overflow = buildProof("0059534ce0bfa19a", 1, 99);
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
    // Odd-y normalisation coverage
    // =========================================================================

    /**
     * SchnorrHW.sign() branches on the parity of the card public key's
     * y-coordinate: if P.y is odd it must sign with d = n − d instead of d. On
     * real cards the parity is a coin flip per card, so getting that branch
     * wrong would break half the fleet.
     *
     * Under jCardSim the parity is not a coin flip and not even random:
     * KeyPairImpl seeds its EC generator with SecureRandomNullProvider, so
     * every simulator ever created generates the SAME keypair — and that
     * keypair has an even y. No number of fresh installs will ever exercise the
     * odd-y path through the APDU layer.
     *
     * This test pins that fact, because it is the sole justification for
     * SchnorrHWSignTest driving SchnorrHW.sign() directly with chosen keys. If
     * this assertion ever starts failing, jCardSim has gained real key
     * randomness: applet-level parity coverage becomes possible, and the note in
     * SchnorrHWSignTest should be revisited — but the direct test stays, because
     * it is deterministic and this would not be.
     */
    @Test @Order(41)
    @DisplayName("Card signature verifies; jCardSim's fixed key covers only the even-y path")
    void testCardSignatureAndParityCoverageLimit() throws Exception {
        byte[] msg = new byte[32];
        for (int i = 0; i < 32; i++) msg[i] = (byte) (0x5A ^ i);

        byte[] firstPub = null;
        for (int i = 0; i < 5; i++) {
            CardSimulator card = freshCard();
            byte[] pub = card.transmitCommand(
                new CommandAPDU(CLA, INS_GET_PUBKEY, 0, 0, 256)).getData();
            if (firstPub == null) {
                firstPub = pub;
            } else {
                assertArrayEquals(firstPub, pub,
                    "jCardSim is expected to generate an identical keypair on every fresh "
                        + "card (SecureRandomNullProvider). It no longer does — re-read the "
                        + "comment on this test and on SchnorrHWSignTest.");
            }

            ResponseAPDU resp = card.transmitCommand(
                new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, msg, 0, 32, 64));
            assertEquals(SW_OK, resp.getSW(), "card " + i + ": SIGN_ARBITRARY failed");
            assertTrue(schnorrVerify(extractPubkeyX(pub), msg, resp.getData()),
                "card " + i + ": signature must verify against the card's own public key");
        }

        assertFalse(pubkeyYIsOdd(firstPub),
            "jCardSim's fixed keypair is expected to have an even P.y, so the APDU-level "
                + "tests only ever exercise the plain-d path. The odd-y d = n - d branch is "
                + "covered deterministically in SchnorrHWSignTest — check it still is.");
    }

    // =========================================================================
    // GET_BALANCE carry propagation (addUint32)
    // =========================================================================

    @Test @Order(42)
    @DisplayName("GET_BALANCE carries correctly past 2^16 and 2^24")
    void testGetBalanceCarriesAcrossAllBytes() {
        // 4 x 0x00FFFFFF = 0x03FFFFFC, then + 0x01000000 = 0x04FFFFFC.
        // Forces carries out of bytes 3, 2 and 1 — testGetBalanceAfterLoad
        // (1000 + 500) only ever carries out of byte 3.
        for (int i = 0; i < 4; i++) {
            byte[] p = buildProof("0059534ce0bfa19a", 0x00FFFFFFL, i);
            assertEquals(SW_OK,
                transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, p, 0, p.length, 1)).getSW());
        }
        byte[] big = buildProof("0059534ce0bfa19a", 0x01000000L, 9);
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, big, 0, big.length, 1)).getSW());

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(0x04FFFFFCL, readUint32(resp.getData(), 0),
            "4 x 0x00FFFFFF + 0x01000000 must be 0x04FFFFFC");
    }

    @Test @Order(43)
    @DisplayName("GET_BALANCE wraps past 2^32 (addUint32 does not detect overflow)")
    void testGetBalanceWrapsPast2Pow32() {
        byte[] max = buildProof("0059534ce0bfa19a", 0xFFFFFFFFL, 1);
        byte[] two = buildProof("0059534ce0bfa19a", 0x00000002L, 2);
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, max, 0, max.length, 1)).getSW());
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, two, 0, two.length, 1)).getSW());

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(1L, readUint32(resp.getData(), 0),
            "0xFFFFFFFF + 2 wraps to 1: the uint32 accumulator has no overflow "
                + "detection, and the applet reports the wrapped value rather than "
                + "an error. Pinned so the behaviour is a decision, not a surprise.");
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

    /**
     * Install and SELECT a brand-new card. Each one runs genKeyPair() afresh, so
     * successive calls draw independent card keys (and independent P.y parities).
     */
    static CardSimulator freshCard() {
        CardSimulator sim = new CardSimulator();
        sim.installApplet(AIDUtil.create(AID_HEX), CashuApplet.class);
        ResponseAPDU resp = sim.transmitCommand(
            new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR)));
        assertEquals(SW_OK, resp.getSW(), "SELECT on a fresh card should succeed");
        return sim;
    }

    /** Parity of the public key's y-coordinate, from either EC point encoding. */
    static boolean pubkeyYIsOdd(byte[] pubBytes) {
        if (pubBytes.length == 65 && pubBytes[0] == 0x04) {
            return (pubBytes[64] & 1) == 1;          // uncompressed: LSB of Y
        } else if (pubBytes.length == 33) {
            return (pubBytes[0] & 1) == 1;           // compressed: 0x02 even / 0x03 odd
        }
        throw new IllegalArgumentException("Unexpected pubkey length: " + pubBytes.length);
    }

    /**
     * Build a 77-byte proof payload: keyset_id[8] + amount[4] + nonce[32] + C[33].
     *
     * keysetIdHex is hex-decoded to 8 RAW bytes, never ASCII-encoded. A NUT-02
     * keyset id is 16 hex chars, which is exactly 8 bytes raw; storing it as
     * ASCII text would fit only half the id. The 32-byte field is the P2PK
     * nonce, not the secret string — see spec/NUT-XX.md.
     *
     * Short ids are rejected rather than zero-padded: padding made a half id
     * look like a working one, which is exactly the class of bug this file is
     * meant to catch.
     */
    static byte[] buildProof(String keysetIdHex, long amount, int seed) {
        if (keysetIdHex.length() != 16) {
            throw new IllegalArgumentException(
                "keyset id must be 16 hex chars (8 raw bytes), got " + keysetIdHex.length()
                + ": " + keysetIdHex);
        }
        byte[] proof = new byte[77];
        // keyset_id: 8 raw bytes from the hex string
        byte[] kid = hexToBytes(keysetIdHex);
        System.arraycopy(kid, 0, proof, 0, 8);
        // amount: big-endian uint32
        proof[8]  = (byte)((amount >> 24) & 0xFF);
        proof[9]  = (byte)((amount >> 16) & 0xFF);
        proof[10] = (byte)((amount >> 8)  & 0xFF);
        proof[11] = (byte)( amount        & 0xFF);
        // nonce: 32 bytes filled with seed value
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

    // =========================================================================
    // D13 — PIN-gated spend/sign
    // =========================================================================

    private void personalise() {
        assertEquals(SW_OK, transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length)).getSW());
    }

    private ResponseAPDU loadProof1() {
        return transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1));
    }

    private byte[] spendMessage() {
        byte[] msg = new byte[32];
        for (int i = 0; i < 32; i++) msg[i] = (byte) (0xA0 + i);
        return msg;
    }

    private ResponseAPDU verifyPin(String pin) {
        byte[] b = pin.getBytes();
        return transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, b, 0, b.length));
    }

    @Test @Order(20)
    @DisplayName("SPEND_PROOF without a verified session is 6982 when a PIN is set (D13)")
    void testSpendRequiresPinWhenSet() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64));
        assertEquals(0x6982, resp.getSW(), "unverified session must not spend");

        // The gate runs before the burn: the slot is intact.
        ResponseAPDU proof = transmit(new CommandAPDU(CLA, 0x13, 0, 0, 78));
        assertEquals(0x01, proof.getData()[0] & 0xFF, "slot must still be unspent");
    }

    @Test @Order(21)
    @DisplayName("SPEND_PROOF after VERIFY_PIN in the same session works")
    void testSpendWithVerifiedPin() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        assertEquals(SW_OK, transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length)).getSW());

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(64, resp.getData().length, "BIP-340 signature expected");
    }

    @Test @Order(22)
    @DisplayName("a wrong PIN burns nothing and decrements the retry counter")
    void testSpendWrongPinLeavesSlotIntact() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        byte[] wrong = "9999".getBytes();
        ResponseAPDU wrongResp = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, wrong, 0, wrong.length));
        assertEquals(0x63C2, wrongResp.getSW(), "63CX with 2 tries remaining");

        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64));
        assertEquals(0x6982, resp.getSW());
        ResponseAPDU proof = transmit(new CommandAPDU(CLA, 0x13, 0, 0, 1));
        assertEquals(0x01, proof.getData()[0] & 0xFF, "slot unspent after failed verify");
    }

    @Test @Order(23)
    @DisplayName("SIGN_ARBITRARY is gated like SPEND_PROOF (D13)")
    void testSignArbitraryGatedWhenPinSet() {
        personalise();
        ResponseAPDU gated = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, spendMessage(), 0, 32, 64));
        assertEquals(0x6982, gated.getSW());

        assertEquals(SW_OK, transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length)).getSW());
        ResponseAPDU resp = transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, spendMessage(), 0, 32, 64));
        assertEquals(SW_OK, resp.getSW());
        assertEquals(64, resp.getData().length);
    }

    // =========================================================================
    // ENG-615 — a blocked PIN must keep gating, not stop gating
    // =========================================================================

    @Test @Order(24)
    @DisplayName("a blocked PIN still gates every PIN-gated command (ENG-615)")
    void testBlockedPinStillGatesEveryCommand() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();

        // Exhaust the three tries. Before the fix this left pinState at 2,
        // which `requirePinIfSet` did not recognise as "a PIN exists" — so a
        // thief who failed three times got a card that spent without asking.
        for (int i = 0; i < 2; i++) {
            transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN, 0, WRONG_PIN.length));
        }
        ResponseAPDU last = transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, WRONG_PIN, 0, WRONG_PIN.length));
        assertEquals(SW_PIN_BLOCKED, last.getSW(), "third wrong PIN blocks the card");
        byte[] info = transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData();
        assertEquals(2, info[7] & 0xFF, "GET_INFO reports the PIN as blocked");

        // Every gated command must now refuse — and SPEND_PROOF must refuse
        // before it burns.
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "SPEND_PROOF on a blocked card");
        assertEquals(0x01, transmit(new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 78)).getData()[0] & 0xFF,
            "the slot is intact: the gate ran before the burn");
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "SIGN_ARBITRARY on a blocked card");
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_1, 0, PROOF_1.length, 1)).getSW(),
            "LOAD_PROOF on a blocked card");
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1)).getSW(),
            "CLEAR_SPENT on a blocked card");
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE)).getSW(),
            "LOCK_CARD on a blocked card");

        // No route may re-key a blocked PIN. SET_PIN is the dangerous one:
        // OwnerPIN.update() resets the try counter, so if SET_PIN read
        // "blocked" as "no PIN" (the ENG-615 shape, one token away) a thief
        // would set their own PIN, verify it and spend. CHANGE_PIN needs a
        // verified session, which a blocked card can never grant.
        assertEquals(SW_CONDITIONS_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN, 0, NEW_PIN.length)).getSW(),
            "SET_PIN cannot re-personalise a blocked card");
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_CHANGE_PIN, 0, 0, changePinData(TEST_PIN, NEW_PIN))).getSW(),
            "CHANGE_PIN cannot re-key a blocked card");
        assertEquals(SW_PIN_BLOCKED,
            transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, NEW_PIN, 0, NEW_PIN.length)).getSW(),
            "the PIN SET_PIN offered did not take");
        assertEquals(SW_PIN_BLOCKED,
            transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length)).getSW(),
            "and the real PIN is refused too");
        assertEquals(2, transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData()[7] & 0xFF,
            "still blocked after every attempt to get back in");

        // Reads stay open: the holder can still see what is stranded.
        assertEquals(SW_OK, transmit(new CommandAPDU(CLA, INS_GET_BALANCE, 0, 0, 4)).getSW());

        // The sequence a thief actually sends: VERIFY_PIN on the blocked card
        // (6983), then the gated command. VERIFY_PIN answers a blocked card
        // before its PIN check, so a session flag written on that early path
        // would open every gate while the card still reports itself blocked.
        // Checking the gate only before these attempts cannot see that.
        assertGatedCommandsRefuse("after SET_PIN, CHANGE_PIN and VERIFY_PIN attempts on a blocked card");
    }

    @Test @Order(25)
    @DisplayName("a failed CHANGE_PIN costs a try, ends the session, and counts toward the block (ENG-615)")
    void testChangePinFailureEndsTheSessionAndCountsTowardTheBlock() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));

        // A verified session, then a CHANGE_PIN carrying the wrong current
        // PIN. On v0.2 this path decremented the counter without touching
        // pinState and left the session verified, so three in a row ran the
        // counter to zero while GET_INFO still said "set", and the session
        // stayed open throughout.
        byte[] wrongCurrent = changePinData(WRONG_PIN, NEW_PIN);
        assertEquals(0x63C2, changePin(wrongCurrent), "a wrong current PIN costs a try");

        // The failed check ended the session, as OwnerPIN.check resets its own
        // validated flag. The next CHANGE_PIN stops at 6982 without reaching
        // the PIN (the counter holds at 2), the right current PIN cannot
        // re-key from here either, and nothing the session had unlocked is
        // still open. On v0.2 the second call answered 63C1 and the third 63C0.
        assertEquals(SW_SECURITY_NOT_SATIS, changePin(wrongCurrent),
            "the next CHANGE_PIN never reaches the PIN check");
        assertEquals(SW_SECURITY_NOT_SATIS, changePin(changePinData(TEST_PIN, NEW_PIN)),
            "not even with the right current PIN: the session is gone");
        assertGatedCommandsRefuse("after a failed CHANGE_PIN");

        // The CHANGE_PIN failure counted: two wrong VERIFY_PINs now block the
        // card, not three, and the block is reported the same way as any other.
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN),
            "the CHANGE_PIN failure counted toward the block");
        assertEquals(2, transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData()[7] & 0xFF,
            "GET_INFO reports the PIN as blocked");

        // Blocked, and neither route re-keys it: CHANGE_PIN has no session to
        // run in, in this session or the next. After re-SELECT the gate holds
        // and neither PIN verifies, so the new one was never installed.
        assertEquals(SW_SECURITY_NOT_SATIS, changePin(changePinData(TEST_PIN, NEW_PIN)),
            "CHANGE_PIN with the right current PIN on a blocked card");
        assertEquals(SW_OK,
            transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR))).getSW(),
            "re-SELECT starts a new session");
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "the gate holds for every session after that");
        assertEquals(SW_SECURITY_NOT_SATIS, changePin(changePinData(TEST_PIN, NEW_PIN)),
            "CHANGE_PIN in the new session");
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN), "the old PIN is refused");
        assertEquals(SW_PIN_BLOCKED, verify(NEW_PIN), "and the new one was never installed");
        assertGatedCommandsRefuse("after VERIFY_PIN attempts on a blocked card, in a new session");
    }

    @Test @Order(26)
    @DisplayName("one wrong VERIFY_PIN after a right one ends the session (OwnerPIN.check semantics)")
    void testFailedVerifyEndsAVerifiedSession() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));

        // OwnerPIN.check resets its validated flag before it compares, so a
        // wrong PIN ends whatever the session had proved. On v0.2 this session
        // stayed verified and the spend below answered 9000.
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertGatedCommandsRefuse("after a wrong VERIFY_PIN in a verified session");

        // Not a lockout: the right PIN verifies again (resetting the counter)
        // and the session spends.
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "a fresh verify re-opens the session");
    }

    @Test @Order(27)
    @DisplayName("blocking the PIN from a verified session leaves that session nothing (ENG-615)")
    void testBlockingFromAVerifiedSessionClosesIt() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));

        // Verify, then three wrong PINs in the same session. The card now
        // reports itself blocked (GET_INFO 2, VERIFY_PIN 6983); on v0.2 this
        // session still spent, signed, loaded and locked — "looks locked, is
        // open", scoped to one tap. The session has to agree with the card.
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN), "third wrong PIN blocks the card");
        assertEquals(2, transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData()[7] & 0xFF,
            "GET_INFO reports the PIN as blocked");
        assertGatedCommandsRefuse("in the session the card was blocked from");
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN), "and the right PIN cannot re-open it");
        assertGatedCommandsRefuse("after the right PIN was refused on the blocked card");
    }

    // -------------------------------------------------------------------------
    // ENG-615 helpers
    // -------------------------------------------------------------------------

    /** CHANGE_PIN data: 1-byte old PIN length, old PIN, new PIN. */
    private static byte[] changePinData(byte[] oldPin, byte[] newPin) {
        byte[] data = new byte[1 + oldPin.length + newPin.length];
        data[0] = (byte) oldPin.length;
        System.arraycopy(oldPin, 0, data, 1, oldPin.length);
        System.arraycopy(newPin, 0, data, 1 + oldPin.length, newPin.length);
        return data;
    }

    private int verify(byte[] pin) {
        return transmit(new CommandAPDU(CLA, INS_VERIFY_PIN, 0, 0, pin, 0, pin.length)).getSW();
    }

    private int changePin(byte[] data) {
        return transmit(new CommandAPDU(CLA, INS_CHANGE_PIN, 0, 0, data)).getSW();
    }

    // =========================================================================
    // D15 — CLEAR_PIN: a holder removes the PIN and the card is bearer again
    // =========================================================================

    /** CLEAR_PIN data: 1-byte PIN length, PIN — CHANGE_PIN's old-PIN framing, nothing after it. */
    static byte[] clearPinData(byte[] pin) {
        byte[] data = new byte[1 + pin.length];
        data[0] = (byte) pin.length;
        System.arraycopy(pin, 0, data, 1, pin.length);
        return data;
    }

    private int clearPin(byte[] pin) {
        return transmit(new CommandAPDU(CLA, INS_CLEAR_PIN, 0, 0, clearPinData(pin))).getSW();
    }

    private int pinState() {
        return transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData()[7] & 0xFF;
    }

    private int reselect() {
        return transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hexToBytes(AID_STR))).getSW();
    }

    @Test @Order(40)
    @DisplayName("CLEAR_PIN needs a verified session: 6982 on a fresh card, a personalised card, and after a failed check (D15)")
    void testClearPinNeedsAVerifiedSession() {
        assertEquals(SW_OK, loadProof1().getSW());

        // No PIN: nothing to clear, and nothing to verify, so the session gate
        // answers before the data is read. Not 6984 — the gate is the same
        // one CHANGE_PIN has, and it runs first.
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "CLEAR_PIN on a card with no PIN");
        assertEquals(0, pinState());

        // A PIN, no VERIFY_PIN: the right PIN in the data field is not enough.
        // A thief who knows the PIN can verify anyway; one who does not must
        // not get a second oracle. Nothing changes and no try is spent.
        personalise();
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "CLEAR_PIN without VERIFY_PIN");
        assertEquals(1, pinState(), "the PIN is still set");
        assertGatedCommandsRefuse("after an unverified CLEAR_PIN");
        assertEquals(0x63C2, verify(WRONG_PIN), "the unverified CLEAR_PIN cost no try");

        // A verified session that a wrong VERIFY_PIN then ended.
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "CLEAR_PIN after the session ended");
        assertEquals(1, pinState());
    }

    @Test @Order(41)
    @DisplayName("a wrong PIN in CLEAR_PIN costs a try, ends the session, counts toward the block, and a blocked PIN is never cleared (D15, ENG-615)")
    void testClearPinWrongPinCountsTowardTheBlockAndABlockedPinStays() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));

        // The wrong PIN goes through failPinCheck like CHANGE_PIN's: 63C2, and
        // the session is over. The next CLEAR_PIN, right PIN or wrong, stops
        // at the gate without reaching the check, so the counter holds at 2:
        // CLEAR_PIN cannot be guessed against faster than VERIFY_PIN can.
        assertEquals(0x63C2, clearPin(WRONG_PIN), "a wrong PIN costs a try");
        assertEquals(1, pinState(), "the PIN is still set");
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(WRONG_PIN), "the next CLEAR_PIN never reaches the check");
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "not even with the right PIN: the session is gone");
        assertGatedCommandsRefuse("after a failed CLEAR_PIN");

        // The failure counted: two more wrong VERIFY_PINs block the card.
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN), "the CLEAR_PIN failure counted toward the block");
        assertEquals(2, pinState(), "GET_INFO reports the PIN as blocked");

        // Blocked is not clearable. The one ENG-615 shape this command could
        // reintroduce is "state 2 reads as clearable": a holder — or anyone,
        // VERIFY_PIN is unauthenticated — blocks the PIN and then removes it,
        // which is the unblock path D13 says does not exist, open to all. The
        // gate refuses in this session, in the next, and with the right PIN.
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "CLEAR_PIN with the right PIN on a blocked card");
        assertEquals(2, pinState(), "still blocked");
        assertGatedCommandsRefuse("after CLEAR_PIN on a blocked card");
        assertEquals(SW_OK, reselect(), "re-SELECT starts a new session");
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "CLEAR_PIN in the new session");
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN), "VERIFY_PIN cannot open one");
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "CLEAR_PIN after that");
        assertEquals(2, pinState(), "a blocked PIN stays blocked");
        assertGatedCommandsRefuse("after every attempt to clear a blocked card");
    }

    @Test @Order(42)
    @DisplayName("CLEAR_PIN removes the PIN: GET_INFO 0.5 / 0x0F / state 0, VERIFY_PIN 6984, and spend, sign, load and clear open with no PIN (D15)")
    void testClearPinRemovesThePinAndTheCardIsBearerAgain() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));

        assertEquals(SW_OK, clearPin(TEST_PIN));

        byte[] info = transmit(new CommandAPDU(CLA, INS_GET_INFO, 0, 0, 256)).getData();
        assertEquals(0x00, info[0] & 0xFF, "major version");
        assertEquals(0x05, info[1] & 0xFF, "minor version: 0.5 is the first build with CLEAR_PIN");
        assertEquals(0x0F, info[6] & 0xFF, "capability bit 3 says the card answers CLEAR_PIN");
        assertEquals(0, info[7] & 0xFF, "PIN state is unset again");
        assertEquals(SW_PIN_NOT_SET, verify(TEST_PIN), "VERIFY_PIN has nothing to verify");
        assertEquals(SW_PIN_NOT_SET, verify(WRONG_PIN), "and nothing to count a try against");

        // D12 semantics, in this session with no VERIFY_PIN having succeeded
        // since the clear: every gated command is open, as on a card that was
        // never personalised.
        ResponseAPDU spend = transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64));
        assertEquals(SW_OK, spend.getSW(), "SPEND_PROOF with no PIN");
        assertEquals(64, spend.getData().length);
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "SIGN_ARBITRARY with no PIN");
        ResponseAPDU load = transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_2, 0, PROOF_2.length, 1));
        assertEquals(SW_OK, load.getSW(), "LOAD_PROOF with no PIN");
        assertEquals(1, load.getData()[0], "into the next free slot");
        ResponseAPDU cleared = transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1));
        assertEquals(SW_OK, cleared.getSW(), "CLEAR_SPENT with no PIN");
        assertEquals(1, cleared.getData()[0], "the spent slot was freed");

        // And in the next session, which starts with no verification at all.
        assertEquals(SW_OK, reselect());
        assertEquals(0, pinState());
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 1, 0, spendMessage(), 0, 32, 64)).getSW(),
            "SPEND_PROOF in a fresh session with no PIN");
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "nothing left to clear");
    }

    @Test @Order(43)
    @DisplayName("SET_PIN works again after CLEAR_PIN and re-gates spending with fresh tries; the cleared session does not carry over (D15)")
    void testSetPinAfterClearPinRegatesSpending() {
        assertEquals(SW_OK, loadProof1().getSW());
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, clearPin(TEST_PIN));

        // "Once" is once per PIN lifecycle: the card is back where SET_PIN
        // found it.
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, NEW_PIN, 0, NEW_PIN.length)).getSW(),
            "SET_PIN after CLEAR_PIN");
        assertEquals(1, pinState());
        assertEquals(SW_CONDITIONS_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_SET_PIN, 0, 0, TEST_PIN, 0, TEST_PIN.length)).getSW(),
            "and only once: the second SET_PIN is refused as before");

        // The VERIFY_PIN that authorised the clear verified a PIN that is
        // gone. CLEAR_PIN ended that session, so the new PIN gates at once.
        assertGatedCommandsRefuse("after SET_PIN in the session that cleared the old PIN");
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(NEW_PIN), "CLEAR_PIN needs a fresh VERIFY_PIN too");

        // The old PIN is gone, the counter is fresh (3 tries), and the new
        // PIN opens the gate.
        assertEquals(0x63C2, verify(TEST_PIN), "the old PIN is refused, and the counter started at 3");
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "the new PIN spends");

        // The cycle closes: the new PIN clears too.
        assertEquals(SW_OK, clearPin(NEW_PIN));
        assertEquals(0, pinState());
    }

    @Test @Order(44)
    @DisplayName("CLEAR_PIN after LOCK_CARD is 6986, before the session gate and the check (D15)")
    void testClearPinOnLockedCard() {
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, transmit(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE)).getSW());

        // Locked is locked: a verified session with the right PIN cannot
        // clear it, and the refusal is the lock's (6986), not the gate's.
        assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, clearPin(TEST_PIN), "CLEAR_PIN on a locked card");
        assertEquals(1, pinState(), "the PIN is still set");
        assertEquals(0x63C2, verify(WRONG_PIN), "the refused CLEAR_PIN cost no try");
        assertEquals(ISO7816.SW_COMMAND_NOT_ALLOWED, clearPin(TEST_PIN),
            "6986 whether or not the session is verified");

        // A card locked with no PIN set cannot gain one either way (SET_PIN
        // is 6986 on a locked card), so CLEAR_PIN's 6986 there is just the
        // lock; the fresh-card case is covered in testClearPinNeedsAVerifiedSession.
    }

    @Test @Order(45)
    @DisplayName("CLEAR_PIN with a bad length is 6700 and costs no try (D15)")
    void testClearPinWrongLength() {
        personalise();
        assertEquals(SW_OK, verify(TEST_PIN));

        // Empty data: no length byte to read.
        assertEquals(SW_WRONG_LENGTH,
            transmit(new CommandAPDU(CLA, INS_CLEAR_PIN, 0, 0, new byte[0])).getSW(),
            "no data");
        // A length byte outside 4..8.
        assertEquals(SW_WRONG_LENGTH,
            transmit(new CommandAPDU(CLA, INS_CLEAR_PIN, 0, 0, new byte[] { 3, 0x31, 0x32, 0x33 })).getSW(),
            "PIN length 3");
        assertEquals(SW_WRONG_LENGTH,
            transmit(new CommandAPDU(CLA, INS_CLEAR_PIN, 0, 0, new byte[] { 9, 1, 2, 3, 4, 5, 6, 7, 8, 9 })).getSW(),
            "PIN length 9");
        // A length byte that does not match Lc: a stray byte is never read as
        // PIN, and a short PIN is never checked.
        byte[] stray = new byte[1 + TEST_PIN.length + 1];
        System.arraycopy(clearPinData(TEST_PIN), 0, stray, 0, 1 + TEST_PIN.length);
        assertEquals(SW_WRONG_LENGTH,
            transmit(new CommandAPDU(CLA, INS_CLEAR_PIN, 0, 0, stray)).getSW(),
            "a byte after the PIN");
        byte[] truncated = { (byte) TEST_PIN.length, 0x31, 0x32, 0x33 };
        assertEquals(SW_WRONG_LENGTH,
            transmit(new CommandAPDU(CLA, INS_CLEAR_PIN, 0, 0, truncated)).getSW(),
            "a PIN shorter than its length byte");

        // None of that reached the PIN check: the session is still verified,
        // the PIN still set, the counter untouched.
        assertEquals(1, pinState());
        assertEquals(SW_OK,
            transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "the session is still verified");
        assertEquals(SW_OK, clearPin(TEST_PIN), "and the well-formed CLEAR_PIN works");
        assertEquals(0, pinState());
    }

    /**
     * Every PIN-gated command answers 6982, and SPEND_PROOF refuses before it
     * burns. Expects slot 0 to hold an unspent proof on entry. LOCK_CARD comes
     * last: were the gate open it would lock the card for good, and a locked
     * card answers LOAD_PROOF / CLEAR_SPENT with 6986 before their gate runs.
     */
    private void assertGatedCommandsRefuse(String when) {
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_SPEND_PROOF, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "SPEND_PROOF " + when);
        assertEquals(0x01, transmit(new CommandAPDU(CLA, INS_GET_PROOF, 0, 0, 78)).getData()[0] & 0xFF,
            "the slot is intact " + when + ": the gate ran before the burn");
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_SIGN_ARBITRARY, 0, 0, spendMessage(), 0, 32, 64)).getSW(),
            "SIGN_ARBITRARY " + when);
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_LOAD_PROOF, 0, 0, PROOF_2, 0, PROOF_2.length, 1)).getSW(),
            "LOAD_PROOF " + when);
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_CLEAR_SPENT, 0, 0, 1)).getSW(),
            "CLEAR_SPENT " + when);
        assertEquals(SW_SECURITY_NOT_SATIS,
            transmit(new CommandAPDU(CLA, INS_LOCK_CARD, 0, 0xDE)).getSW(),
            "LOCK_CARD " + when);
    }
}
