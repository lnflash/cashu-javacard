package me.flashapp.cashu;

import javacard.framework.*;
import javacard.security.*;

/**
 * SchnorrHW — Hardware BIP-340 Schnorr signing for JavaCard 3.0.5+
 *
 * This class replaces the BigInteger-based simulation in CashuApplet with a
 * JavaCard-native implementation. It uses only APIs from:
 *   javacard.framework.*
 *   javacard.security.*
 *
 * No java.math, java.security, java.util, or System.arraycopy.
 *
 * --- Signing algorithm (BIP-340 default signing) ---
 *
 *   1. If P.y is odd, d_eff = n − d  (normalise to even-y key)
 *   2. a = 32 fresh bytes from RandomData.ALG_SECURE_RANDOM
 *      t = d_eff XOR SHA256_tagged("BIP0340/aux", a)
 *   3. k = SHA256_tagged("BIP0340/nonce", t ‖ P.x ‖ msg) mod n
 *   4. R = k·G  (via KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY)
 *   5. If R.y is odd, k = n − k
 *   6. e = SHA256_tagged("BIP0340/challenge", R.x ‖ P.x ‖ msg) mod n
 *   7. s = (k + e·d_eff) mod n   (using mulModN + addModN)
 *   8. sig = R.x ‖ s (64 bytes)
 *
 *   Steps 2–3 are BIP-340's *default signing* nonce derivation, auxiliary
 *   randomness and all — not a deterministic RFC6979-style nonce. This matters
 *   on a bearer card: a nonce that is a pure function of (d, msg) hands a fault
 *   injector two signatures over the same k, and d = (s1−s2)/(e1−e2) then falls
 *   straight out. Folding fresh aux randomness into t is precisely the
 *   mitigation BIP-340 specifies, so signatures over the same message are
 *   deliberately NOT reproducible. See SchnorrHWSignTest#signUsesAFreshNonce.
 *
 * --- Modular arithmetic ---
 *
 *   All 256-bit arithmetic is over Z_n where n is the secp256k1 group order.
 *
 *   mulModN uses schoolbook 256×256 → 512-bit product, then reduces via the
 *   identity  2^256 ≡ DELTA (mod n)  where DELTA = 2^256 − n (≈ 2^128).
 *   The reduction applies the identity twice (depth-2) to bring the result
 *   to < 2n, followed by a single conditional subtract.
 *
 * --- Memory discipline ---
 *
 *   JavaCard Classic allocates `new` in persistent EEPROM/Flash and never
 *   collects it: an allocation on the signing path is a permanent leak that
 *   bricks the card after a few hundred taps. Every buffer this class uses is
 *   therefore allocated ONCE — in the constructor / init(), at install time —
 *   as CLEAR_ON_DESELECT transient memory, and threaded down through the
 *   arithmetic helpers as explicit (work, workOff) parameters.
 *
 *   No `new` may appear anywhere outside the constructor and init().
 *
 *   Transient footprint: `sc` (256 B scratchpad) + `work` (288 B arithmetic
 *   scratch, see WORK_LEN).
 *
 * ENG-182 — lnflash/cashu-javacard
 */
final class SchnorrHW {

    // ── secp256k1 group order n ────────────────────────────────────────────
    //
    // This is the ONE value every modular helper in this class reduces against.
    // The caller also hands the group order in through the constructor (see
    // Nparam) because the EC key objects need it via setR(); init() asserts the
    // two agree, so a typo in CashuApplet.SECP256K1_N fails `gp --install`
    // rather than producing signatures that are well-formed and universally
    // rejected.
    private static final byte[] N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
        (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
        (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
    };

    /**
     * DELTA = 2^256 mod n = 2^256 − n
     *
     * n  = FFFF...FFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
     * 2^256 = 1 0000...0000
     * DELTA = 0000...0001 45512319 50B75FC4 402DA173 2FC9BEBF
     *
     * Derived from N, and therefore not independently editable: every reduction
     * below is only correct while N + DELTA == 2^256 exactly. init() asserts
     * that identity at install time alongside the N/Nparam agreement check.
     */
    private static final byte[] DELTA = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x45,(byte)0x51,(byte)0x23,(byte)0x19,(byte)0x50,(byte)0xB7,(byte)0x5F,(byte)0xC4,
        (byte)0x40,(byte)0x2D,(byte)0xA1,(byte)0x73,(byte)0x2F,(byte)0xC9,(byte)0xBE,(byte)0xBF
    };

    // ── Precomputed tag hashes (set once at install time) ─────────────────
    // SHA256("BIP0340/aux"), SHA256("BIP0340/nonce") and SHA256("BIP0340/challenge")
    // Stored in EEPROM, initialised by init().
    private final byte[] tagHashAux;       // 32 bytes
    private final byte[] tagHashNonce;     // 32 bytes
    private final byte[] tagHashChallenge; // 32 bytes

    // ── Transient scratchpad (CLEAR_ON_DESELECT, 256 bytes) ────────────────
    // Layout (non-overlapping during signing):
    //   [  0.. 31]  d_eff     — private key scalar (normalised)
    //   [ 32.. 63]  Px        — public key x-coordinate
    //   [ 64.. 95]  k         — nonce scalar
    //   [ 96..191]  tmp96     — hash input / intermediate (96 bytes)
    //   [192..223]  e         — challenge scalar
    //   [224..255]  ed        — e * d_eff mod n
    private final byte[] sc;
    private static final short SC_D    = (short)  0;
    private static final short SC_PX   = (short) 32;
    private static final short SC_K    = (short) 64;
    private static final short SC_TMP  = (short) 96;
    private static final short SC_E    = (short)192;
    private static final short SC_ED   = (short)224;

    // ── Transient arithmetic scratch (CLEAR_ON_DESELECT, WORK_LEN bytes) ──
    // Threaded into mulModN as (work, workOff) so that nothing on the signing
    // path ever calls `new`. Layout, relative to workOff:
    //   [  0.. 63]  prod       — 512-bit a*b product           (mulModN)
    //   [ 64..127]  t          — 512-bit p_hi*DELTA            (reduce512toModN)
    //   [128..191]  t2         — 512-bit t_hi*DELTA            (reduce512toModN)
    //   [192..223]  hiContrib  — 256-bit t2_hi*DELTA           (reduce512toModN)
    //   [224..287]  full       — 512-bit scratch               (mulSmallByDelta)
    /** Bytes of scratch mulModN needs; callers must supply at least this much. */
    static final short WORK_LEN      = (short)288;
    /** Offsets inside the work buffer handed to reduce512toModN. */
    private static final short W_PROD = (short)  0;
    private static final short W_RED  = (short) 64;   // reduce512toModN's region
    private static final short W_T    = (short)  0;   // relative to W_RED
    private static final short W_T2   = (short) 64;
    private static final short W_HI   = (short)128;
    private static final short W_SUB  = (short)160;   // mulSmallByDelta's region
    private final byte[] work;

    // ── Crypto objects (allocated once) ───────────────────────────────────
    private final MessageDigest sha256;
    private final KeyAgreement  ecdh;      // ALG_EC_SVDP_DH_PLAIN_XY
    private final ECPrivateKey  tmpPriv;   // reused temp key for k
    private final RandomData    rng;       // BIP-340 auxiliary randomness (step 2)
    // NB: there is deliberately no ECPublicKey for the generator. R = k*G is
    // computed by handing the raw 65-byte G to generateSecret(), so a key object
    // for G would be built, parameterised and then never read — dead weight in
    // EEPROM and one more thing to keep in sync with the curve parameters.

    // ── secp256k1 curve parameters (shared with CashuApplet) ──────────────
    // Passed in via constructor to avoid code duplication.
    private final byte[] G;   // 65-byte uncompressed generator
    private final byte[] P;   // 32-byte field prime
    private final byte[] A;   // 32-byte a=0
    private final byte[] B;   // 32-byte b=7
    private final byte[] Nparam; // 32-byte group order (same as N above)

    // ── Constructor ───────────────────────────────────────────────────────

    SchnorrHW(byte[] secp256k1G, byte[] secp256k1P,
              byte[] secp256k1A, byte[] secp256k1B,
              byte[] secp256k1N) {
        G      = secp256k1G;
        P      = secp256k1P;
        A      = secp256k1A;
        B      = secp256k1B;
        Nparam = secp256k1N;

        tagHashAux       = new byte[32];
        tagHashNonce     = new byte[32];
        tagHashChallenge = new byte[32];

        sc     = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
        work   = JCSystem.makeTransientByteArray(WORK_LEN,   JCSystem.CLEAR_ON_DESELECT);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Temp private key slot for k (reused each sign call)
        tmpPriv = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        setECParams(tmpPriv, null);

        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);

        // BIP-340 auxiliary randomness. Allocated once, like everything else on
        // the signing path.
        //
        // ALG_SECURE_RANDOM (and generateData) are marked deprecated in the
        // 3.0.5 API in favour of ALG_TRNG / ALG_PRESEEDED_DRBG / nextBytes, and
        // the CAP build prints a warning for each. That is deliberate: the
        // replacements are 3.0.5-era additions that not every 3.0.5+ part
        // actually implements, and getInstance on an unsupported algorithm
        // throws CryptoException at install. ALG_SECURE_RANDOM is present
        // everywhere this applet can run. Revisit only with a card in hand.
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }

    /**
     * Must be called once during applet install (after constructor) to
     * precompute and store the BIP-340 tag hashes in EEPROM, to verify that the
     * curve constants this class reduces against agree with the ones the caller
     * installs on the key objects, and to verify that this card's ECDH
     * implementation frames its output the way sign() reads it.
     */
    void init() {
        // ── Curve-constant agreement ─────────────────────────────────────
        // Two representations of the group order exist: N, used by every
        // modular helper here, and Nparam, handed to setR() on the EC key
        // objects (and, in CashuApplet, to the card keypair). If they ever
        // disagree — a typo in CashuApplet.SECP256K1_N, or this class reused
        // for another curve — the ECDH scalar multiply runs on one order while
        // addModN/mulModN/subtractFromN run on another, and every signature is
        // well-formed and universally rejected. Fail `gp --install` instead.
        if (Nparam.length != (short)32
                || Util.arrayCompare(N, (short)0, Nparam, (short)0, (short)32) != (byte)0) {
            ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
        }

        // DELTA is defined as 2^256 − N, i.e. N + DELTA must be exactly 2^256:
        // a 256-bit sum of zero with a carry out. mulModN's whole reduction
        // rests on that identity, so it is checked rather than commented.
        // Uses sc as scratch — allocated already, and nothing has signed yet at
        // install time. probeEcdhFraming() clobbers the same bytes below.
        if (add32(N, (short)0, DELTA, (short)0, sc, (short)0) != (short)1) {
            ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
        }
        for (short i = 0; i < 32; i++) {
            if (sc[i] != (byte)0) {
                ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
            }
        }

        // SHA256("BIP0340/aux")  — tag is 11 ASCII bytes
        byte[] tagAux = { 'B','I','P','0','3','4','0','/','a','u','x' };
        sha256.reset();
        sha256.doFinal(tagAux, (short)0, (short)11, tagHashAux, (short)0);

        // SHA256("BIP0340/nonce")  — tag is 13 ASCII bytes
        byte[] tagNonce = { 'B','I','P','0','3','4','0','/','n','o','n','c','e' };
        sha256.reset();
        sha256.doFinal(tagNonce, (short)0, (short)13, tagHashNonce, (short)0);

        // SHA256("BIP0340/challenge")  — tag is 17 ASCII bytes
        byte[] tagChallenge = {
            'B','I','P','0','3','4','0','/','c','h','a','l','l','e','n','g','e'
        };
        sha256.reset();
        sha256.doFinal(tagChallenge, (short)0, (short)17, tagHashChallenge, (short)0);

        // Probe using the transient scratchpad rather than a fresh array: a
        // `new byte[80]` here would be persistent EEPROM that is orphaned the
        // moment init() returns and never reclaimed, which is precisely what
        // the memory-discipline note on this class forbids. `sc` is already
        // allocated, is 256 B, and nothing has signed yet at install time.
        probeEcdhFraming(sc);
    }

    /**
     * Verify once, at install time, that ALG_EC_SVDP_DH_PLAIN_XY returns the
     * 65-byte {@code 04 ‖ X ‖ Y} framing that sign() indexes into.
     *
     * Deliberately scoped to the ECDH framing and nothing else. An earlier
     * version also asserted that {@code getS} left-pads to 32 bytes, which was
     * wrong twice over: it asserted it on {@code tmpPriv} — a key loaded here
     * by {@code setS}, not the {@code cardPrivKey} that {@code sign()} actually
     * reads — so a card that echoes back whatever length setS was handed while
     * reporting a stripped length for generated keys sailed through the probe
     * and failed in sign(); and a card returning fewer than 32 bytes is
     * spec-legal, so the check refused to install on hardware that works.
     * sign() right-aligns the scalar instead.
     *
     * The framing is a property of the card, not of the message, so a card that
     * returns the bare 64-byte X‖Y is wrong on the very first tap and wrong on
     * every tap after it. Discovering that inside sign() is far too late:
     * CashuApplet marks the proof SPENT before it calls doSign, so an
     * incompatible card would burn one slot per attempt and hand back 6F00 each
     * time until the balance was gone — with the proofs unredeemable, because
     * they are P2PK-locked to a key whose card can no longer sign. Throwing here
     * fails the {@code gp --install} instead, before a single proof is loaded.
     *
     * @param probe scratch of at least 80 bytes, owned by the caller. Sized well
     *              above the expected 65 so that a card returning more trips the
     *              length check below rather than an
     *              ArrayIndexOutOfBoundsException. Its first 80 bytes are
     *              clobbered.
     */
    private void probeEcdhFraming(byte[] probe) {
        // Zero the scalar explicitly — the buffer is shared scratch, not a
        // freshly allocated (and therefore zeroed) array.
        Util.arrayFillNonAtomic(probe, (short)0, (short)80, (byte)0);
        probe[31] = (byte)0x02;              // throwaway scalar d = 2, so R = 2G
        tmpPriv.setS(probe, (short)0, (short)32);

        ecdh.init(tmpPriv);
        short len = ecdh.generateSecret(G, (short)0, (short)65, probe, (short)0);
        if (len != (short)65 || probe[0] != (byte)0x04) {
            ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
        }
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * BIP-340 Schnorr sign using JavaCard hardware APIs.
     *
     * @param privKey  card's secp256k1 EC private key
     * @param pubKey   card's secp256k1 EC public key (for P.y parity check)
     * @param msg      source buffer containing exactly 32-byte message
     * @param msgOff   offset of message in source buffer
     * @param out      output buffer (must have ≥ 64 bytes from outOff)
     * @param outOff   offset in output buffer
     * @return 64 (signature byte length)
     */
    short sign(ECPrivateKey privKey, ECPublicKey pubKey,
               byte[] msg, short msgOff,
               byte[] out, short outOff) {

        // ── Step 1: Extract d, check P.y parity ──────────────────────
        // getS is specified to return the scalar's byte length, with the value
        // right-aligned in the caller's buffer. It is NOT specified to left-pad
        // to the key size, so a card that strips leading zero bytes is entirely
        // spec-legal — and roughly one generated key in 256 has a zero high
        // byte. Two things therefore must not happen here:
        //
        //   * trusting the length blindly. Everything below reads d as exactly
        //     32 bytes at sc[SC_D..SC_D+31]; a short answer would fold the tail
        //     of the shared scratchpad into d, and every signature the card
        //     emitted would fail verification while its proofs stayed
        //     P2PK-locked to that key — unspendable.
        //   * refusing the card. The key is generated on-card at install time
        //     and can have a zero high byte by pure luck, so rejecting a short
        //     length would brick a card's worth of bearer money at random.
        //
        // Right-aligning handles both, and is correct on every spec-legal card.
        short dLen = privKey.getS(sc, SC_D);   // d at sc[SC_D..SC_D+dLen-1]
        if (dLen < (short)1 || dLen > (short)32) {
            ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
        }
        if (dLen < (short)32) {
            short pad = (short)(32 - dLen);
            // Backwards, byte by byte: source and destination overlap inside
            // sc, and the JavaCard spec does not promise arrayCopyNonAtomic
            // behaves like memmove when they do.
            for (short i = (short)(dLen - 1); i >= (short)0; i--) {
                sc[(short)(SC_D + pad + i)] = sc[(short)(SC_D + i)];
            }
            // Not a fresh array: sc is long-lived scratch that still holds the
            // previous signature's bytes, so the pad must be written, not
            // assumed.
            Util.arrayFillNonAtomic(sc, SC_D, pad, (byte)0);
        }

        // Get public key point W (uncompressed 65 bytes or compressed 33 bytes)
        short wLen = pubKey.getW(sc, SC_TMP);  // W at sc[96..]
        boolean pyOdd;
        if (wLen == (short)65) {
            // Uncompressed: 04 || Px(32) || Py(32)
            // A 65-byte W whose lead byte is not 0x04 is not a point encoding we
            // understand. Falling through to the compressed branch here would
            // read the "parity" out of a byte that is not a parity byte and emit
            // a signature no mint can verify, so refuse instead.
            if (sc[SC_TMP] != (byte)0x04) {
                ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
            }
            // P.y is sc[TMP+33..TMP+64]; parity = LSB of last byte
            pyOdd = (sc[(short)(SC_TMP + 64)] & 1) == 1;
            Util.arrayCopy(sc, (short)(SC_TMP + 1), sc, SC_PX, (short)32);
        } else if (wLen == (short)33
                   && (sc[SC_TMP] == (byte)0x02 || sc[SC_TMP] == (byte)0x03)) {
            // Compressed: prefix 02 (even) or 03 (odd)
            pyOdd = (sc[SC_TMP] & 1) == 1;
            Util.arrayCopy(sc, (short)(SC_TMP + 1), sc, SC_PX, (short)32);
        } else {
            ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
            return (short)0;   // unreachable; keeps pyOdd definitely assigned
        }

        if (pyOdd) {
            subtractFromN(sc, SC_D, sc, SC_D);   // d = n − d
        }

        // ── Step 2: t = d_eff XOR taggedHash("BIP0340/aux", a) ───────
        // BIP-340 default signing. `a` is fresh secure randomness per signature;
        // it is what stops a fault-injected repeat of this call from reusing k.
        // sc[TMP..TMP+31] = a, sc[TMP+32..TMP+63] = taggedHash(aux, a) -> t
        rng.generateData(sc, SC_TMP, (short)32);
        taggedHash(tagHashAux, sc, SC_TMP, (short)32, sc, (short)(SC_TMP+32));
        for (short i = 0; i < 32; i++) {
            sc[(short)(SC_TMP+32+i)] =
                (byte)(sc[(short)(SC_TMP+32+i)] ^ sc[(short)(SC_D+i)]);
        }

        // ── Step 3: k = taggedHash("BIP0340/nonce", t ‖ P.x ‖ msg) mod n
        // sc[TMP..TMP+95] = t(32) || Px(32) || msg(32)
        Util.arrayCopy(sc,  (short)(SC_TMP+32), sc, SC_TMP,          (short)32); // t
        Util.arrayCopy(sc,  SC_PX,              sc, (short)(SC_TMP+32),(short)32); // Px
        Util.arrayCopy(msg, msgOff,             sc, (short)(SC_TMP+64),(short)32); // msg
        taggedHash(tagHashNonce, sc, SC_TMP, (short)96, sc, SC_K);
        reduceModN(sc, SC_K);         // k = k mod n (in place)

        // ── Step 4: R = k·G via ECDH coprocessor ─────────────────────
        // Load k into temp private key, compute [k]G
        tmpPriv.setS(sc, SC_K, (short)32);
        ecdh.init(tmpPriv);
        // Result = 65-byte uncompressed point at sc[TMP]; we need 65 bytes
        // sc[TMP..TMP+64] = 04 || Rx(32) || Ry(32)
        //
        // ALG_EC_SVDP_DH_PLAIN_XY output framing is NOT uniform across
        // implementations — some cards return the bare 64-byte X||Y. Everything
        // below reads Rx at SC_TMP+1 and the y-parity at SC_TMP+64, so an
        // unexpected framing would silently shift both by one byte and emit
        // well-formed signatures that no mint can verify.
        //
        // probeEcdhFraming() already rejected such a card at install time, so
        // this is a cheap assert on a condition that cannot change between taps;
        // it is not the place the incompatibility is meant to be discovered.
        short rLen = ecdh.generateSecret(G, (short)0, (short)65, sc, SC_TMP);
        if (rLen != (short)65 || sc[SC_TMP] != (byte)0x04) {
            ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
        }

        // ── Step 5: if R.y is odd, k = n − k ─────────────────────────
        boolean ryOdd = (sc[(short)(SC_TMP + 64)] & 1) == 1;
        if (ryOdd) {
            subtractFromN(sc, SC_K, sc, SC_K);
        }
        // Rx is at sc[TMP+1..TMP+32]

        // ── Step 6: e = taggedHash("BIP0340/challenge", Rx ‖ Px ‖ msg) mod n
        // Re-use sc[TMP..TMP+95] for the 96-byte input
        // sc[TMP..TMP+31]  = Rx  (already there at SC_TMP+1, shift left by 1)
        Util.arrayCopy(sc, (short)(SC_TMP+1), sc, SC_TMP,          (short)32); // Rx
        Util.arrayCopy(sc, SC_PX,             sc, (short)(SC_TMP+32),(short)32); // Px
        Util.arrayCopy(msg, msgOff,           sc, (short)(SC_TMP+64),(short)32); // msg
        taggedHash(tagHashChallenge, sc, SC_TMP, (short)96, sc, SC_E);
        reduceModN(sc, SC_E);         // e = e mod n

        // ── Step 7: s = (k + e·d) mod n ──────────────────────────────
        mulModN(sc, SC_E, sc, SC_D, sc, SC_ED, work, (short)0);  // ed = e * d mod n
        addModN(sc, SC_ED, sc, SC_K, out, (short)(outOff + 32)); // s = ed + k mod n

        // ── Step 8: output = Rx ‖ s ──────────────────────────────────
        // Rx sits at sc[SC_TMP..SC_TMP+31] — step 6 shifted it there before
        // hashing; the challenge hash wrote to SC_E, not SC_TMP.
        Util.arrayCopy(sc, SC_TMP, out, outOff, (short)32);  // Rx

        return (short)64;
    }

    // ── Tagged hash ───────────────────────────────────────────────────────

    /**
     * BIP-340 tagged hash:  SHA256(tagHash ‖ tagHash ‖ msg)
     *
     * @param tagHash  precomputed SHA256(tag),  32 bytes
     * @param msg      message buffer
     * @param msgOff   offset in msg
     * @param msgLen   length of message
     * @param out      output buffer (receives 32-byte hash)
     * @param outOff   offset in output buffer
     */
    private void taggedHash(byte[] tagHash,
                            byte[] msg, short msgOff, short msgLen,
                            byte[] out, short outOff) {
        sha256.reset();
        sha256.update(tagHash, (short)0, (short)32);
        sha256.update(tagHash, (short)0, (short)32);
        sha256.doFinal(msg, msgOff, msgLen, out, outOff);
    }

    // ── Modular arithmetic ────────────────────────────────────────────────

    /**
     * Compute a mod n in-place (a is 32 bytes, big-endian).
     *
     * If a ≥ n, subtracts n (at most once, since callers guarantee a < 2n
     * after the tagged-hash reduction step).
     */
    private static void reduceModN(byte[] a, short aOff) {
        if (cmp32(a, aOff, N, (short)0) >= 0) {
            sub32(a, aOff, N, (short)0, a, aOff);
        }
    }

    /**
     * out = (a + b) mod n   — 256-bit inputs, 256-bit output.
     * All buffers are big-endian.
     */
    static void addModN(byte[] a, short aOff, byte[] b, short bOff,
                        byte[] out, short outOff) {
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short sum = (short)((a[(short)(aOff+i)] & 0xFF)
                              + (b[(short)(bOff+i)] & 0xFF)
                              + carry);
            out[(short)(outOff+i)] = (byte)sum;
            carry = (short)((sum >>> 8) & 1);
        }
        // carry > 0 means sum ≥ 2^256 > n, so subtract n
        if (carry != 0 || cmp32(out, outOff, N, (short)0) >= 0) {
            sub32(out, outOff, N, (short)0, out, outOff);
        }
    }

    /**
     * out = a * b mod n   — schoolbook 256×256 → 512-bit product,
     * then two-level DELTA reduction.
     *
     * DELTA = 2^256 mod n ≈ 2^128.
     * 2^256 ≡ DELTA (mod n)
     *
     * For 512-bit product p = p_hi·2^256 + p_lo:
     *   p mod n = (p_hi·DELTA + p_lo) mod n
     *
     * p_hi·DELTA ≤ (n-1)·DELTA < n·2^128 → 384 bits → split again:
     *   = q_hi·2^256 + q_lo  (q_hi < DELTA < 2^128)
     *   q_hi·DELTA < 2^128·2^128 = 2^256 < 2n
     *
     * So two iterations bring us to < 2n; final subtractIfGe finishes.
     *
     * Allocates nothing: all 288 bytes of temporary storage come from the
     * caller-supplied `work` buffer (see WORK_LEN and the layout map at the
     * top of the class). `work` must not overlap `out`, `a` or `b`.
     *
     * @param a       256-bit input A (32 bytes, big-endian)
     * @param aOff    offset of A
     * @param b       256-bit input B (32 bytes, big-endian)
     * @param bOff    offset of B
     * @param out     32-byte output buffer
     * @param outOff  offset in output buffer
     * @param work    scratch buffer, ≥ WORK_LEN bytes from workOff
     * @param workOff offset of the scratch region
     */
    static void mulModN(byte[] a, short aOff,
                        byte[] b, short bOff,
                        byte[] out, short outOff,
                        byte[] work, short workOff) {
        mul256x256(a, aOff, b, bOff, work, (short)(workOff + W_PROD));
        reduce512toModN(work, (short)(workOff + W_PROD),
                        out, outOff,
                        work, (short)(workOff + W_RED));
    }

    /**
     * Schoolbook 256×256 → 512-bit unsigned multiplication.
     * a[32], b[32] → out[64], all big-endian.
     */
    private static void mul256x256(byte[] a, short aOff,
                                   byte[] b, short bOff,
                                   byte[] out, short outOff) {
        // JavaCard has no int, so everything below is short arithmetic.
        // Per step: ai*bj + cur + carry <= 255*255 + 255 + 255 = 65535, i.e.
        // exactly 16 bits. A signed short holds those bits (it may read as
        // negative); masking recovers the true byte values, so the result is
        // exact. High byte is taken with (x >> 8) & 0xFF — an arithmetic
        // shift on the sign-extended value still yields the correct byte.
        Util.arrayFillNonAtomic(out, outOff, (short)64, (byte)0);
        for (short i = 31; i >= 0; i--) {
            short ai = (short)(a[(short)(aOff+i)] & 0xFF);
            if (ai == 0) continue;
            short carry = 0;
            for (short j = 31; j >= 0; j--) {
                short bj  = (short)(b[(short)(bOff+j)] & 0xFF);
                short pos = (short)(outOff + i + j + 1);
                short cur = (short)(out[pos] & 0xFF);
                short prod = (short)((short)(ai * bj) + cur + carry);
                out[pos]  = (byte)(prod & 0xFF);
                carry     = (short)((prod >> 8) & 0xFF);
            }
            // propagate carry into upper bytes
            short pos = (short)(outOff + i);
            while (carry != 0 && pos >= outOff) {
                short s = (short)((short)(out[pos] & 0xFF) + carry);
                out[pos--] = (byte)(s & 0xFF);
                carry      = (short)((s >> 8) & 0xFF);
            }
        }
    }

    /**
     * Reduce a 512-bit value (64 bytes, big-endian) to 256-bit mod n.
     * Uses depth-2 DELTA reduction.  Result in out[32].
     *
     * Allocates nothing: needs 224 bytes of scratch from work[workOff..].
     * `work` must not overlap `p` or `out`.
     */
    private static void reduce512toModN(byte[] p, short pOff,
                                        byte[] out, short outOff,
                                        byte[] work, short workOff) {
        short tOff  = (short)(workOff + W_T);   // 64 bytes
        short t2Off = (short)(workOff + W_T2);  // 64 bytes
        short hiOff = (short)(workOff + W_HI);  // 32 bytes

        // p = p_hi * 2^256 + p_lo
        // Step 1: t = p_hi * DELTA  (256×32-eff → 256 bits after mod-n reduction)
        // t fits in 48 bytes worst-case, but we compute mod-n in two steps.
        mul256x256(p, pOff, DELTA, (short)0, work, tOff);
        // t = (p_hi * DELTA)_hi * 2^256 + (p_hi * DELTA)_lo
        // Apply identity again to t_hi part:
        mul256x256(work, tOff, DELTA, (short)0, work, t2Off);
        // t2_hi * DELTA < 2^128 * 2^128 = 2^256 < 2n → directly add, then subtract
        // Sum = t2_lo + t[32..63] + p[pOff+32..pOff+63]
        // But t2_hi is tiny (< 2^127), its contribution via DELTA:
        //   t2_hi * DELTA < 2^256 fits in 32 bytes.
        mulSmallByDelta(work, t2Off, work, hiOff, work, (short)(workOff + W_SUB));
        // Now sum = hiContrib + t2[32..63] + t[32..63] + p[32..63]
        short carry = add4x32(work, hiOff,
                work, (short)(t2Off+32),
                work, (short)(tOff+32),
                p, (short)(pOff+32),
                out, outOff);
        // The four-term sum can exceed 2^256. Each overflow unit is a dropped
        // 2^256, and 2^256 ≡ DELTA (mod n), so fold it back rather than losing
        // it. Adding DELTA can itself overflow, hence the loop; carry shrinks
        // rapidly (DELTA < 2^129) so this terminates after a couple of rounds.
        while (carry != 0) {
            short pending = carry;
            carry = 0;
            for (short i = 0; i < pending; i++) {
                carry = (short)(carry
                        + add32(out, outOff, DELTA, (short)0, out, outOff));
            }
        }
        // Final reduction: at most 2–3 conditional subtracts
        while (cmp32(out, outOff, N, (short)0) >= 0) {
            sub32(out, outOff, N, (short)0, out, outOff);
        }
    }

    /**
     * out = a * DELTA, truncated to 256 bits.
     *
     * <b>Requires a &lt; 2^127.</b> DELTA is a 129-bit value, so a·DELTA is up to
     * 385 bits in general and would NOT fit in the 32-byte output — the earlier
     * claim that "the top 32 bytes are all zero because a &lt; 2^256 and delta &lt;
     * 2^128" was simply false. The precondition holds only because the sole
     * caller passes the high half of t2, which the depth-2 DELTA reduction
     * bounds far below 2^127.
     *
     * The precondition is <i>enforced</i>, not assumed: if the top 32 bytes of
     * the 512-bit product are non-zero the value did not fit, and we throw
     * rather than hand a silently truncated result back into the reduction.
     *
     * Unlike the ECDH framing check, this one cannot be hoisted to install time:
     * it is an assertion about an intermediate of <i>this</i> multiplication,
     * not a fixed property of the card. It is unreachable for every input the
     * depth-2 reduction can produce — reaching it means the arithmetic above is
     * wrong, in which case a spent slot is the smaller loss.
     *
     * @param a       operand, 32 bytes big-endian at a[aOff..aOff+31]
     * @param out     32-byte output buffer
     * @param work    scratch, ≥ 64 bytes from workOff; must not overlap a or out
     */
    private static void mulSmallByDelta(byte[] a, short aOff,
                                        byte[] out, short outOff,
                                        byte[] work, short workOff) {
        mul256x256(a, aOff, DELTA, (short)0, work, workOff);
        for (short i = 0; i < 32; i++) {
            if (work[(short)(workOff + i)] != (byte)0) {
                ISOException.throwIt(CashuApplet.SW_CRYPTO_ERROR);
            }
        }
        Util.arrayCopy(work, (short)(workOff + 32), out, outOff, (short)32);
    }

    /**
     * out = low 256 bits of (a + b + c + d), four 32-byte big-endian terms.
     *
     * This does NOT reduce mod n. It returns the carry out of bit 255, which the
     * caller MUST fold back as carry·DELTA (each dropped 2^256 is worth DELTA
     * mod n). Discarding the return value silently corrupts the reduction.
     *
     * @return carry out of bit 255 (0..3 for four 256-bit terms)
     */
    private static short add4x32(byte[] a, short aOff,
                                 byte[] b, short bOff,
                                 byte[] c, short cOff,
                                 byte[] d, short dOff,
                                 byte[] out, short outOff) {
        // Max per step: 4*255 + carry <= 1024, well inside a signed short.
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short s = (short)((short)(a[(short)(aOff+i)] & 0xFF)
                            + (short)(b[(short)(bOff+i)] & 0xFF)
                            + (short)(c[(short)(cOff+i)] & 0xFF)
                            + (short)(d[(short)(dOff+i)] & 0xFF)
                            + carry);
            out[(short)(outOff+i)] = (byte)(s & 0xFF);
            carry = (short)((s >> 8) & 0xFF);
        }
        // The caller MUST fold this carry back in: each unit of carry is a
        // dropped 2^256, which is worth DELTA (mod n). Returning it instead of
        // discarding it fixes mulModN for sums that overflow 256 bits.
        return carry;
    }

    /**
     * out = a + b for 32-byte big-endian values.
     *
     * @return carry out of the most significant byte (0 or 1)
     */
    private static short add32(byte[] a, short aOff,
                               byte[] b, short bOff,
                               byte[] out, short outOff) {
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short s = (short)((short)(a[(short)(aOff+i)] & 0xFF)
                            + (short)(b[(short)(bOff+i)] & 0xFF)
                            + carry);
            out[(short)(outOff+i)] = (byte)(s & 0xFF);
            carry = (short)((s >> 8) & 0xFF);
        }
        return carry;
    }

    // ── Utility ───────────────────────────────────────────────────────────

    /**
     * out = n − a  (modular negation in Z_n), 32 bytes each, big-endian.
     */
    static void subtractFromN(byte[] a, short aOff, byte[] out, short outOff) {
        sub32(N, (short)0, a, aOff, out, outOff);
    }

    /**
     * 256-bit subtraction: out = a − b.  Assumes a ≥ b (no underflow check).
     */
    private static void sub32(byte[] a, short aOff,
                               byte[] b, short bOff,
                               byte[] out, short outOff) {
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short diff = (short)((a[(short)(aOff+i)] & 0xFF)
                               - (b[(short)(bOff+i)] & 0xFF)
                               - borrow);
            if (diff < 0) { diff += 256; borrow = 1; } else { borrow = 0; }
            out[(short)(outOff+i)] = (byte)diff;
        }
    }

    /**
     * Compare two 32-byte big-endian values.
     * @return negative / 0 / positive as a < b / a == b / a > b.
     */
    private static short cmp32(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < 32; i++) {
            short ai = (short)(a[(short)(aOff+i)] & 0xFF);
            short bi = (short)(b[(short)(bOff+i)] & 0xFF);
            if (ai != bi) return (short)(ai - bi);
        }
        return (short)0;
    }

    /**
     * Set secp256k1 EC curve parameters on a private and/or public key.
     * Either key may be null (only the non-null one is configured).
     */
    private void setECParams(ECPrivateKey priv, ECPublicKey pub) {
        if (priv != null) {
            priv.setFieldFP(P, (short)0, (short)32);
            priv.setA(A, (short)0, (short)32);
            priv.setB(B, (short)0, (short)32);
            priv.setG(G, (short)0, (short)65);
            priv.setR(Nparam, (short)0, (short)32);
            priv.setK((short)1);
        }
        if (pub != null) {
            pub.setFieldFP(P, (short)0, (short)32);
            pub.setA(A, (short)0, (short)32);
            pub.setB(B, (short)0, (short)32);
            pub.setG(G, (short)0, (short)65);
            pub.setR(Nparam, (short)0, (short)32);
            pub.setK((short)1);
        }
    }
}
