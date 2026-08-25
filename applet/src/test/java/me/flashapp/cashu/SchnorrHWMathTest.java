package me.flashapp.cashu;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Math-level tests for SchnorrHW's hand-rolled 256-bit modular arithmetic.
 *
 * These deliberately bypass the card/APDU layer and check the primitives
 * directly against java.math.BigInteger, so that a failing BIP-340 signature
 * can be attributed to either the modular arithmetic or the higher-level
 * signing logic rather than guessed at.
 */
class SchnorrHWMathTest {

    /** secp256k1 group order n. */
    private static final BigInteger N = new BigInteger(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    private static byte[] to32(BigInteger v) {
        byte[] out = new byte[32];
        byte[] raw = v.toByteArray();
        int len = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - len, out, 32 - len, len);
        return out;
    }

    private static BigInteger from32(byte[] b) {
        return new BigInteger(1, b);
    }

    /** Deterministic seed so failures are reproducible. */
    private static Random rng() {
        return new Random(0xCA54D00DL);
    }

    @Test
    @DisplayName("addModN matches BigInteger (a + b) mod n")
    void addModNMatchesBigInteger() {
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.addModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0);
            assertEquals(a.add(b).mod(N), from32(out),
                "addModN mismatch at iteration " + i + " (a=" + a.toString(16)
                    + ", b=" + b.toString(16) + ")");
        }
    }

    @Test
    @DisplayName("mulModN matches BigInteger (a * b) mod n")
    void mulModNMatchesBigInteger() {
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0);
            assertEquals(a.multiply(b).mod(N), from32(out),
                "mulModN mismatch at iteration " + i + " (a=" + a.toString(16)
                    + ", b=" + b.toString(16) + ")");
        }
    }

    @Test
    @DisplayName("mulModN handles edge values (0, 1, n-1)")
    void mulModNEdgeCases() {
        BigInteger[] vals = { BigInteger.ZERO, BigInteger.ONE, N.subtract(BigInteger.ONE),
                              BigInteger.TWO, N.shiftRight(1) };
        for (BigInteger a : vals) {
            for (BigInteger b : vals) {
                byte[] out = new byte[32];
                SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0);
                assertEquals(a.multiply(b).mod(N), from32(out),
                    "mulModN edge mismatch a=" + a.toString(16) + " b=" + b.toString(16));
            }
        }
    }

    @Test
    @DisplayName("mul256x256 (raw 512-bit product) matches BigInteger a*b")
    void mul256x256MatchesBigInteger() throws Exception {
        java.lang.reflect.Method m = SchnorrHW.class.getDeclaredMethod(
            "mul256x256", byte[].class, short.class, byte[].class, short.class,
            byte[].class, short.class);
        m.setAccessible(true);
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] prod = new byte[64];
            m.invoke(null, to32(a), (short) 0, to32(b), (short) 0, prod, (short) 0);
            assertEquals(a.multiply(b), new BigInteger(1, prod),
                "mul256x256 mismatch at iteration " + i);
        }
    }
}
