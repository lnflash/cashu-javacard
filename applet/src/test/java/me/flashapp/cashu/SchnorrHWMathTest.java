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
     * The methods that are allowed to allocate, per source file: everything that
     * runs exactly once at install time. Anything else in these files is
     * reachable from an APDU handler.
     *
     * Entry format: { file name, install-time declaration, ... }. The
     * declarations are matched literally against the comment-stripped source, so
     * they must be unique in it — {@code "private CashuApplet()"} rather than
     * {@code "CashuApplet()"}, which would also hit the {@code new CashuApplet()}
     * inside install().
     *
     * Every .java file under src/main/java/me/flashapp/cashu must appear here;
     * a new one with no entry fails the test rather than slipping through
     * unchecked.
     *
     * "Runs exactly once at install time" is itself enforced, not taken on
     * trust: {@link #assertNoAllocationOutside} requires every unqualified call
     * to a listed method to sit inside another listed method's body. A helper
     * like {@code initCardKeypair()} is only install-time for as long as nobody
     * wires it to an APDU handler, and a whole-body allocation waiver granted on
     * the strength of a comment is exactly how the leak this test guards against
     * would come back.
     */
    private static final String[][] INSTALL_TIME_METHODS = {
        { "SchnorrHW.java",
          "SchnorrHW(", "void init()" },
        { "CashuApplet.java",
          "public static void install(", "private CashuApplet()",
          "private void initCardKeypair()" },
    };

    /**
     * JavaCard Classic allocates `new` in persistent EEPROM/Flash and never
     * collects it, so a single `new byte[]` on an APDU path leaks the card's
     * persistent memory a few dozen bytes per tap until every write command
     * throws. jCardSim runs on the JVM heap with a real GC and therefore cannot
     * surface this — only a source-level check can. It is CONTRIBUTING.md
     * principle 5, and this test is its enforcement.
     *
     * Both applet sources are scanned, not just the signer: {@code CashuApplet}
     * is every bit as much on the APDU path, and a stray {@code byte[] tmp = new
     * byte[64]} inside processLoadProof would leak exactly the same way.
     */
    @Test
    @DisplayName("no applet source allocates outside its install-time methods")
    void noAllocationOutsideInstallTime() throws Exception {
        java.nio.file.Path dir = mainSourceDir();
        java.util.List<java.nio.file.Path> sources;
        try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.list(dir)) {
            sources = s.filter(p -> p.getFileName().toString().endsWith(".java"))
                       .sorted()
                       .collect(java.util.stream.Collectors.toList());
        }
        org.junit.jupiter.api.Assertions.assertFalse(sources.isEmpty(),
            "no applet sources found under " + dir.toAbsolutePath());

        java.util.Set<String> scanned = new java.util.HashSet<>();
        for (java.nio.file.Path p : sources) {
            String name = p.getFileName().toString();
            String[] installTime = installTimeMethods(name);
            assertNoAllocationOutside(name,
                new String(java.nio.file.Files.readAllBytes(p),
                    java.nio.charset.StandardCharsets.UTF_8),
                installTime);
            scanned.add(name);
        }

        for (String[] entry : INSTALL_TIME_METHODS) {
            org.junit.jupiter.api.Assertions.assertTrue(scanned.contains(entry[0]),
                "INSTALL_TIME_METHODS names " + entry[0] + ", which no longer exists under "
                + dir.toAbsolutePath() + " — the allow-list is stale");
        }
    }

    /**
     * The guard above is only worth anything if it can say no, so it is pointed
     * at sources written to fail it.
     *
     * The waived-helper leak is the one this exists for: {@code initThing()}
     * allocates and is allow-listed, which is fine while only the constructor
     * calls it. The moment an APDU handler calls it too, every tap allocates a
     * new array in EEPROM — and the allocation itself never moved, so the plain
     * allocation scan stays green. Only the call-site check catches it.
     */
    @Test
    @DisplayName("the allow-list rejects an install-time helper called from the APDU path")
    void allowListRejectsInstallTimeHelperCalledFromApduPath() {
        String[] allowList = {
            "public static void install(", "private Fake()", "private void initThing()"
        };

        String clean =
            "class Fake {\n"
            + "    private byte[] buf;\n"
            + "    public static void install(byte[] a, short b, byte c) { new Fake(); }\n"
            + "    private Fake() { initThing(); }\n"
            + "    private void initThing() { buf = new byte[64]; }\n"
            + "    private void processApdu() { buf[0] = 1; }\n"
            + "}\n";
        assertNoAllocationOutside("Fake.java", clean, allowList);

        String leaky = clean.replace(
            "private void processApdu() { buf[0] = 1; }",
            "private void processApdu() { initThing(); }");
        org.opentest4j.AssertionFailedError failed =
            org.junit.jupiter.api.Assertions.assertThrows(
                org.opentest4j.AssertionFailedError.class,
                () -> assertNoAllocationOutside("Fake.java", leaky, allowList),
                "an allow-listed allocating helper reached from the APDU path must fail");
        org.junit.jupiter.api.Assertions.assertTrue(failed.getMessage().contains("initThing"),
            "the failure must name the helper that gained an APDU-path caller, got: "
                + failed.getMessage());
    }

    /**
     * A call on another object that merely shares a name with an allow-listed
     * method is not a call to it — {@code ecdh.init(tmpPriv)} in SchnorrHW is
     * exactly that, and flagging it would make the guard unusable.
     */
    @Test
    @DisplayName("the call-site check ignores calls qualified by a receiver")
    void allowListIgnoresQualifiedSameNameCalls() {
        String src =
            "class Fake {\n"
            + "    private byte[] buf;\n"
            + "    private Other other;\n"
            + "    public static void install(byte[] a, short b, byte c) { new Fake(); }\n"
            + "    private Fake() { initThing(); }\n"
            + "    private void initThing() { buf = new byte[64]; }\n"
            + "    private void processApdu() { other.initThing(); }\n"
            + "}\n";
        assertNoAllocationOutside("Fake.java", src, new String[] {
            "public static void install(", "private Fake()", "private void initThing()"
        });
    }

    /** The install-time declarations registered for a source file. */
    private static String[] installTimeMethods(String fileName) {
        for (String[] entry : INSTALL_TIME_METHODS) {
            if (entry[0].equals(fileName)) {
                return java.util.Arrays.copyOfRange(entry, 1, entry.length);
            }
        }
        throw new org.opentest4j.AssertionFailedError(
            fileName + " is on the APDU path but has no entry in INSTALL_TIME_METHODS. "
            + "Add one listing the methods that run once at install time (constructor, "
            + "install(), anything called only from them) so the rest of the file is "
            + "checked for persistent-memory allocation.");
    }

    /**
     * Fails if the source allocates anywhere inside a method body other than the
     * given install-time declarations.
     */
    private static void assertNoAllocationOutside(String fileName, String rawSrc,
                                                  String[] installTimeDeclarations) {
        String src = stripCommentsAndCharLiterals(rawSrc);

        int[][] allowedRanges = new int[installTimeDeclarations.length][];
        for (int i = 0; i < installTimeDeclarations.length; i++) {
            allowedRanges[i] = bodyRange(src, installTimeDeclarations[i]);
        }

        assertOnlyCalledAtInstallTime(fileName, src, installTimeDeclarations, allowedRanges);

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
            // inside a method, and only the install-time methods may allocate.
            boolean allowed = depth[at] < 2;
            for (int[] range : allowedRanges) {
                allowed |= at > range[0] && at < range[1];
            }
            if (!allowed) {
                int from = Math.max(0, at - 90);
                int to = Math.min(src.length(), at + 90);
                org.junit.jupiter.api.Assertions.fail(
                    "allocation outside the install-time methods of " + fileName
                    + " leaks persistent EEPROM on every call — allocate once at install "
                    + "time as a CLEAR_ON_DESELECT transient array and thread it through "
                    + "as (work, workOff). Found near:\n..."
                    + src.substring(from, to).replaceAll("\\s+", " ") + "...");
            }
        }
    }

    /**
     * Fails if a method whose whole body is waived as install-time is reachable
     * from anywhere that is not itself waived.
     *
     * The waiver on {@code initCardKeypair()} is only sound while the "called
     * once, from the constructor" claim in its comment holds. Add a
     * {@code 0x4x REGENERATE_KEY} handler that calls it and the leak is back —
     * a fresh {@code KeyPair} in EEPROM per APDU — with the allocation guard
     * still green, because the allocation never moved. So the claim is checked
     * rather than read: every unqualified call to a listed name must sit inside
     * a listed body.
     *
     * Unqualified on purpose. {@code ecdh.init(tmpPriv)} is a call on another
     * object that happens to share a name with {@code SchnorrHW.init()}, and a
     * receiver before the dot is the one signal available without a type
     * checker. The flip side is the known limit of this check: a cross-file
     * {@code schnorrHW.init()} from an APDU handler is invisible to it. Both
     * cross-file entry points here are install-time by construction — the JCRE
     * calls {@code install()}, which calls the constructor — and the guard
     * covers the case that actually rots, which is a local helper quietly
     * gaining a second caller.
     */
    private static void assertOnlyCalledAtInstallTime(String fileName, String src,
                                                      String[] installTimeDeclarations,
                                                      int[][] allowedRanges) {
        for (int i = 0; i < installTimeDeclarations.length; i++) {
            String declaration = installTimeDeclarations[i];
            String name = declaredName(declaration);
            int declAt = src.indexOf(declaration);
            int declEnd = declAt + declaration.length();

            java.util.regex.Matcher calls = java.util.regex.Pattern
                .compile("(?<![.\\w$])" + java.util.regex.Pattern.quote(name) + "\\s*\\(")
                .matcher(src);
            while (calls.find()) {
                int at = calls.start();
                if (at >= declAt && at < declEnd) {
                    continue;   // the declaration itself
                }
                boolean allowed = false;
                for (int[] range : allowedRanges) {
                    allowed |= at > range[0] && at < range[1];
                }
                if (!allowed) {
                    int from = Math.max(0, at - 90);
                    int to = Math.min(src.length(), at + 90);
                    org.junit.jupiter.api.Assertions.fail(
                        name + "() is on the INSTALL_TIME_METHODS allow-list of " + fileName
                        + ", so its entire body is waived from the no-allocation rule — but "
                        + "it is called from outside every install-time method, i.e. from the "
                        + "APDU path. Either drop the waiver and stop allocating in it, or "
                        + "remove the call. Found near:\n..."
                        + src.substring(from, to).replaceAll("\\s+", " ") + "...");
                }
            }
        }
    }

    /** The method (or constructor) name in a declaration like "private void foo(". */
    private static String declaredName(String declaration) {
        int paren = declaration.indexOf('(');
        if (paren < 0) {
            throw new IllegalStateException(
                "INSTALL_TIME_METHODS entries must name a method: " + declaration);
        }
        int end = paren;
        while (end > 0 && Character.isWhitespace(declaration.charAt(end - 1))) end--;
        int start = end;
        while (start > 0 && Character.isJavaIdentifierPart(declaration.charAt(start - 1))) start--;
        if (start == end) {
            throw new IllegalStateException(
                "no method name found in INSTALL_TIME_METHODS entry: " + declaration);
        }
        return declaration.substring(start, end);
    }

    /** Applet main-source directory, resolved from either module or repo root. */
    private static java.nio.file.Path mainSourceDir() throws java.io.IOException {
        String[] candidates = {
            "src/main/java/me/flashapp/cashu",
            "applet/src/main/java/me/flashapp/cashu",
        };
        for (String c : candidates) {
            java.nio.file.Path p = java.nio.file.Paths.get(c);
            if (java.nio.file.Files.isDirectory(p)) {
                return p;
            }
        }
        throw new java.io.FileNotFoundException(
            "applet sources not found relative to "
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
