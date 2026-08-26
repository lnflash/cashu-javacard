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

    /**
     * Scratch buffer for mulModN. On-card this is a CLEAR_ON_DESELECT transient
     * array allocated once in the SchnorrHW constructor; here a plain array is
     * fine. Deliberately sized from the constant so a future growth of the
     * arithmetic scratch shows up here rather than as an out-of-bounds read.
     */
    private static byte[] work() {
        return new byte[SchnorrHW.WORK_LEN];
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
            SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0,
                work(), (short) 0);
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
                SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0,
                    work(), (short) 0);
                assertEquals(a.multiply(b).mod(N), from32(out),
                    "mulModN edge mismatch a=" + a.toString(16) + " b=" + b.toString(16));
            }
        }
    }

    /**
     * The odd-y normalisation d = n - d is picked at random by the card's key
     * generation (P.y parity), so the applet-level tests only exercise it about
     * half the time on any given run. This pins the primitive deterministically.
     */
    @Test
    @DisplayName("subtractFromN matches BigInteger n - a")
    void subtractFromNMatchesBigInteger() {
        Random r = rng();
        for (int i = 0; i < 200; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.subtractFromN(to32(a), (short) 0, out, (short) 0);
            assertEquals(N.subtract(a), from32(out),
                "subtractFromN mismatch at iteration " + i + " (a=" + a.toString(16) + ")");
        }
    }

    @Test
    @DisplayName("subtractFromN handles edge values (0, 1, n-1)")
    void subtractFromNEdgeCases() {
        BigInteger[] vals = { BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                              N.subtract(BigInteger.ONE), N.shiftRight(1) };
        for (BigInteger a : vals) {
            byte[] out = new byte[32];
            SchnorrHW.subtractFromN(to32(a), (short) 0, out, (short) 0);
            assertEquals(N.subtract(a), from32(out),
                "subtractFromN edge mismatch a=" + a.toString(16));
        }
    }

    /**
     * Reusing one scratch buffer across calls must not leak state between them:
     * on-card the buffer is a single long-lived transient array, so a helper that
     * reads a stale byte instead of writing it first would only misbehave on the
     * second and later signatures.
     */
    @Test
    @DisplayName("mulModN is correct when the work buffer is reused and pre-dirtied")
    void mulModNReusesWorkBufferSafely() {
        Random r = rng();
        byte[] shared = work();
        java.util.Arrays.fill(shared, (byte) 0xA5);
        for (int i = 0; i < 100; i++) {
            BigInteger a = new BigInteger(256, r).mod(N);
            BigInteger b = new BigInteger(256, r).mod(N);
            byte[] out = new byte[32];
            SchnorrHW.mulModN(to32(a), (short) 0, to32(b), (short) 0, out, (short) 0,
                shared, (short) 0);
            assertEquals(a.multiply(b).mod(N), from32(out),
                "mulModN mismatch on reused work buffer at iteration " + i);
        }
    }

    /**
     * JavaCard Classic allocates `new` in persistent EEPROM/Flash and never
     * collects it, so a single `new byte[]` on the signing path leaks the card's
     * persistent memory a few hundred bytes per tap until every SPEND_PROOF and
     * SIGN_ARBITRARY throws. jCardSim runs on the JVM heap with a real GC and
     * therefore cannot surface this — only a source-level check can.
     *
     * Allocation is legal in the constructor and in init(), both of which run
     * exactly once at install time.
     */
    @Test
    @DisplayName("SchnorrHW allocates nothing outside the constructor and init()")
    void noAllocationOutsideInstallTime() throws Exception {
        String src = stripCommentsAndCharLiterals(readSchnorrHWSource());

        int[] ctor = bodyRange(src, "SchnorrHW(");
        int[] init = bodyRange(src, "void init()");

        // `new byte[..]` plus the array-initializer form `byte[] x = { .. }`,
        // which allocates just the same but contains no `new` keyword.
        java.util.regex.Pattern allocation = java.util.regex.Pattern.compile(
            "\\bnew\\b"
            + "|\\b(?:byte|short|int|boolean|Object)\\s*\\[\\s*\\]\\s*\\w+\\s*=\\s*\\{");

        int[] depth = braceDepths(src);

        java.util.regex.Matcher m = allocation.matcher(src);
        while (m.find()) {
            int at = m.start();
            // Depth 1 is the class body: field initialisers run once when the
            // applet is installed, which is exactly what we want. Depth >= 2 is
            // inside a method, and only the constructor and init() may allocate.
            boolean inMethodBody = depth[at] >= 2;
            boolean allowed = !inMethodBody
                || (at > ctor[0] && at < ctor[1])
                || (at > init[0] && at < init[1]);
            if (!allowed) {
                int from = Math.max(0, at - 90);
                int to = Math.min(src.length(), at + 90);
                org.junit.jupiter.api.Assertions.fail(
                    "allocation outside the constructor/init() leaks persistent EEPROM on "
                    + "every call — allocate once at install time as a CLEAR_ON_DESELECT "
                    + "transient array and thread it through as (work, workOff). Found near:\n..."
                    + src.substring(from, to).replaceAll("\\s+", " ") + "...");
            }
        }
    }

    private static String readSchnorrHWSource() throws java.io.IOException {
        String[] candidates = {
            "src/main/java/me/flashapp/cashu/SchnorrHW.java",
            "applet/src/main/java/me/flashapp/cashu/SchnorrHW.java",
        };
        for (String c : candidates) {
            java.nio.file.Path p = java.nio.file.Paths.get(c);
            if (java.nio.file.Files.exists(p)) {
                return new String(java.nio.file.Files.readAllBytes(p),
                    java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        throw new java.io.FileNotFoundException(
            "SchnorrHW.java not found relative to "
            + java.nio.file.Paths.get("").toAbsolutePath());
    }

    /** Drop comments and char literals so `new` and braces are only ever real code. */
    private static String stripCommentsAndCharLiterals(String s) {
        StringBuilder out = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            if (s.startsWith("/*", i)) {
                int e = s.indexOf("*/", i + 2);
                i = (e < 0) ? s.length() : e + 2;
            } else if (s.startsWith("//", i)) {
                int e = s.indexOf('\n', i);
                i = (e < 0) ? s.length() : e;
            } else if (s.charAt(i) == '\'') {
                int j = i + 1;
                while (j < s.length() && s.charAt(j) != '\'') {
                    j += (s.charAt(j) == '\\') ? 2 : 1;
                }
                out.append("' '");
                i = j + 1;
            } else {
                out.append(s.charAt(i));
                i++;
            }
        }
        return out.toString();
    }

    /** Brace nesting depth at every character index. Class body = 1, method body = 2. */
    private static int[] braceDepths(String src) {
        int[] depth = new int[src.length()];
        int d = 0;
        for (int i = 0; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '{') d++;
            depth[i] = d;
            if (c == '}') d--;
        }
        return depth;
    }

    /** [openBraceIndex, closeBraceIndex] of the body following the given declaration. */
    private static int[] bodyRange(String src, String declaration) {
        int decl = src.indexOf(declaration);
        if (decl < 0) throw new IllegalStateException("not found in source: " + declaration);
        int open = src.indexOf('{', decl);
        if (open < 0) throw new IllegalStateException("no body for: " + declaration);
        int depth = 0;
        for (int i = open; i < src.length(); i++) {
            char c = src.charAt(i);
            if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return new int[] { open, i };
        }
        throw new IllegalStateException("unbalanced braces after: " + declaration);
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
