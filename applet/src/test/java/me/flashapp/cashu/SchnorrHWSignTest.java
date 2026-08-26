package me.flashapp.cashu;

import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Drives {@link SchnorrHW#sign} directly with keys of our choosing.
 *
 * Why this cannot be done through the applet: {@code SchnorrHW.sign()} branches
 * on the parity of the card public key's y-coordinate — if P.y is odd it must
 * sign with d = n − d rather than d. On a real card the parity is a coin flip
 * per card. Under jCardSim it is not random at all: {@code KeyPairImpl} seeds
 * its generator with {@code SecureRandomNullProvider}, so every simulator ever
 * created generates the <em>same</em> keypair, and that keypair has an even y
 * (…F678). Installing a thousand simulators exercises the even-y path a
 * thousand times and the odd-y path zero times.
 *
 * That is the whole reason this file exists. A broken d = n − d normalisation
 * would have left every applet-level signature test green while half of all
 * cards in the field produced signatures every mint rejects. Here the private
 * key is chosen, so both branches run on every single test run, deterministically.
 *
 * Public keys are the true d·G values for each d (independently computed), so a
 * wrong point would fail before the signature is even looked at.
 */
class SchnorrHWSignTest {

    // ── secp256k1 parameters, same values the applet installs on its keys ────
    private static final byte[] SECP_P = CashuAppletTest.hexToBytes(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    private static final byte[] SECP_A = new byte[32];
    private static final byte[] SECP_B = CashuAppletTest.hexToBytes(
        "0000000000000000000000000000000000000000000000000000000000000007");
    private static final byte[] SECP_N = CashuAppletTest.hexToBytes(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    private static final byte[] SECP_G = CashuAppletTest.hexToBytes(
        "04"
        + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
        + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

    /** { private key d, uncompressed public key 04||X||Y, "is P.y odd" }. */
    private static final Object[][] KEYS = {
        { "0000000000000000000000000000000000000000000000000000000000000003",
          "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
          + "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672",
          Boolean.FALSE },
        { "0000000000000000000000000000000000000000000000000000000000000002",
          "04C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"
          + "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A",
          Boolean.FALSE },
        { "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
          "04DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
          + "2CE19B946C4EE58546F5251D441A065EA50735606985E5B228788BEC4E582898",
          Boolean.FALSE },
        { "0000000000000000000000000000000000000000000000000000000000000006",
          "04FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
          + "AE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297",
          Boolean.TRUE },
        { "0000000000000000000000000000000000000000000000000000000000000009",
          "04ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE"
          + "CC338921B0A7D9FD64380971763B61E9ADD888A4375F8E0F05CC262AC64F9C37",
          Boolean.TRUE },
        { "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
          "0425D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"
          + "0CFEB7AC4341CB6441C702568A8C0FBDC873B0CF5C8181FDAFE3AEE6F49CD4A9",
          Boolean.TRUE },
    };

    @Test
    @DisplayName("sign() verifies for both P.y parities, including the d = n - d path")
    void signVerifiesForBothPubkeyParities() throws Exception {
        SchnorrHW schnorr = new SchnorrHW(SECP_G, SECP_P, SECP_A, SECP_B, SECP_N);
        schnorr.init();

        byte[] msg = new byte[32];
        for (int i = 0; i < 32; i++) msg[i] = (byte) (0x5A ^ i);

        int evenKeys = 0, oddKeys = 0;
        for (Object[] k : KEYS) {
            byte[] d     = CashuAppletTest.hexToBytes((String) k[0]);
            byte[] w     = CashuAppletTest.hexToBytes((String) k[1]);
            boolean yOdd = (Boolean) k[2];

            assertEquals(65, w.length, "public key must be uncompressed 04||X||Y");
            assertEquals(yOdd, CashuAppletTest.pubkeyYIsOdd(w),
                "test data is inconsistent: declared parity does not match the point");
            if (yOdd) oddKeys++; else evenKeys++;

            ECPrivateKey priv = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
            ECPublicKey pub = (ECPublicKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
            setCurve(priv, pub);
            priv.setS(d, (short) 0, (short) 32);
            pub.setW(w, (short) 0, (short) 65);

            byte[] sig = new byte[64];
            assertEquals(64, schnorr.sign(priv, pub, msg, (short) 0, sig, (short) 0),
                "sign() must report a 64-byte signature");

            assertTrue(CashuAppletTest.schnorrVerify(
                    java.util.Arrays.copyOfRange(w, 1, 33), msg, sig),
                "signature must verify for d=" + k[0] + " (P.y "
                    + (yOdd ? "odd — the d = n - d normalisation is wrong"
                            : "even — the plain-d path is wrong") + ")");
        }

        assertTrue(oddKeys > 0, "no odd-y key in the corpus: the d = n - d branch is untested");
        assertTrue(evenKeys > 0, "no even-y key in the corpus: the plain-d branch is untested");
    }

    /**
     * The scratch buffers are allocated once in the constructor and reused for
     * every signature, so a helper that reads a stale byte instead of writing it
     * would only misbehave from the second signature onward.
     *
     * "Repeatable" here means every call keeps producing a <em>valid</em>
     * signature — not the same bytes. Signature bytes must not repeat; that is
     * the aux-randomness property asserted below and in
     * {@link #signUsesAFreshNonce()}.
     */
    @Test
    @DisplayName("sign() keeps producing valid, non-repeating signatures across many calls")
    void signIsRepeatableAcrossCalls() throws Exception {
        SchnorrHW schnorr = new SchnorrHW(SECP_G, SECP_P, SECP_A, SECP_B, SECP_N);
        schnorr.init();

        // An odd-y key, so the reused-scratch path covers the normalisation too.
        byte[] d = CashuAppletTest.hexToBytes(
            "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710");
        byte[] w = CashuAppletTest.hexToBytes(
            "0425D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"
            + "0CFEB7AC4341CB6441C702568A8C0FBDC873B0CF5C8181FDAFE3AEE6F49CD4A9");
        byte[] pubX = java.util.Arrays.copyOfRange(w, 1, 33);

        ECPrivateKey priv = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        ECPublicKey pub = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        setCurve(priv, pub);
        priv.setS(d, (short) 0, (short) 32);
        pub.setW(w, (short) 0, (short) 65);

        byte[] first = null;
        for (int i = 0; i < 16; i++) {
            byte[] msg = new byte[32];
            java.util.Arrays.fill(msg, (byte) i);
            byte[] sig = new byte[64];
            schnorr.sign(priv, pub, msg, (short) 0, sig, (short) 0);
            assertTrue(CashuAppletTest.schnorrVerify(pubX, msg, sig),
                "signature " + i + " must verify — reused scratch buffers leaked state");

            // Re-signing a fixed message on the same instance must keep verifying
            // no matter how much scratch has been churned since. It must NOT
            // reproduce the earlier signature — see signUsesAFreshNonce below.
            byte[] again = new byte[64];
            byte[] msg0 = new byte[32];
            schnorr.sign(priv, pub, msg0, (short) 0, again, (short) 0);
            assertTrue(CashuAppletTest.schnorrVerify(pubX, msg0, again),
                "re-signature of the all-zero message after call " + i + " must verify");
            if (first == null) {
                first = again;
            } else {
                assertFalse(java.util.Arrays.equals(first, again),
                    "re-signing the same message after call " + i
                        + " reproduced an earlier signature: the nonce is a pure "
                        + "function of (d, msg) and the aux randomness is not reaching k");
            }
        }
    }

    /**
     * The finding this test exists for: {@code sign()} used to derive k as
     * {@code taggedHash("BIP0340/nonce", d ‖ zeros32 ‖ msg)} — a deterministic
     * nonce, under a class header claiming BIP-340. Every such signature
     * verifies, so nothing else in this suite noticed.
     *
     * It matters because this is a bearer card sitting in an attacker-controlled
     * NFC field. With k a pure function of (d, msg), a fault injected after R is
     * emitted but before e is folded in yields two signatures sharing k, and
     * {@code d = (s1 − s2)/(e1 − e2)} recovers the card key outright — every
     * proof on the card, and every proof ever loaded onto it, becomes spendable.
     * BIP-340's auxiliary randomness exists to close exactly this.
     *
     * So: same key, same message, many signatures. Each must verify, and the R
     * values must all differ. A regression to a deterministic nonce collapses
     * every R to one value and fails here.
     *
     * Scoped to a single signer on purpose. jCardSim backs
     * {@code RandomData.ALG_SECURE_RANDOM} with an unseeded BouncyCastle
     * {@code DigestRandomGenerator}, so two freshly constructed simulators walk
     * the same byte stream — comparing signatures <em>across</em> instances
     * would test the simulator's seeding, not the applet. Within one instance
     * the generator advances, which is exactly the property under test.
     */
    @Test
    @DisplayName("sign() draws a fresh nonce per call (BIP-340 aux randomness)")
    void signUsesAFreshNonce() throws Exception {
        SchnorrHW schnorr = new SchnorrHW(SECP_G, SECP_P, SECP_A, SECP_B, SECP_N);
        schnorr.init();

        byte[] d = CashuAppletTest.hexToBytes(
            "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
        byte[] w = CashuAppletTest.hexToBytes(
            "04DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"
            + "2CE19B946C4EE58546F5251D441A065EA50735606985E5B228788BEC4E582898");
        byte[] pubX = java.util.Arrays.copyOfRange(w, 1, 33);

        ECPrivateKey priv = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        ECPublicKey pub = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        setCurve(priv, pub);
        priv.setS(d, (short) 0, (short) 32);
        pub.setW(w, (short) 0, (short) 65);

        byte[] msg = CashuAppletTest.hexToBytes(
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");

        java.util.Set<String> seenR = new java.util.HashSet<>();
        for (int i = 0; i < 24; i++) {
            byte[] sig = new byte[64];
            assertEquals(64, schnorr.sign(priv, pub, msg, (short) 0, sig, (short) 0));
            assertTrue(CashuAppletTest.schnorrVerify(pubX, msg, sig),
                "signature " + i + " over the fixed message must verify");
            String r = bytesToHex(java.util.Arrays.copyOfRange(sig, 0, 32));
            assertTrue(seenR.add(r),
                "R repeated on signature " + i + " over an identical message — the "
                    + "nonce is deterministic, so a fault-injected replay recovers "
                    + "the card private key from the two s values");
        }
        assertEquals(24, seenR.size(), "every signature must use its own nonce");
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }

    private static void setCurve(ECPrivateKey priv, ECPublicKey pub) {
        priv.setFieldFP(SECP_P, (short) 0, (short) 32);
        priv.setA(SECP_A, (short) 0, (short) 32);
        priv.setB(SECP_B, (short) 0, (short) 32);
        priv.setG(SECP_G, (short) 0, (short) 65);
        priv.setR(SECP_N, (short) 0, (short) 32);
        priv.setK((short) 1);

        pub.setFieldFP(SECP_P, (short) 0, (short) 32);
        pub.setA(SECP_A, (short) 0, (short) 32);
        pub.setB(SECP_B, (short) 0, (short) 32);
        pub.setG(SECP_G, (short) 0, (short) 65);
        pub.setR(SECP_N, (short) 0, (short) 32);
        pub.setK((short) 1);
    }
}
