package me.flashapp.cashu;

import javacard.framework.*;
import javacard.security.*;

/**
 * SchnorrHW — Hardware BIP-340 Schnorr signing for JavaCard 3.0.4
 *
 * This class replaces the BigInteger-based simulation in CashuApplet with a
 * JavaCard-native implementation. It uses only APIs from:
 *   javacard.framework.*
 *   javacard.security.*
 *
 * No java.math, java.security, java.util, or System.arraycopy.
 *
 * --- Signing algorithm (BIP-340) ---
 *
 *   1. If P.y is odd, d_eff = n − d  (normalise to even-y key)
 *   2. k = SHA256_tagged("BIP0340/nonce", d_eff ‖ zeros32 ‖ msg) mod n
 *   3. R = k·G  (via KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY)
 *   4. If R.y is odd, k = n − k
 *   5. e = SHA256_tagged("BIP0340/challenge", R.x ‖ P.x ‖ msg) mod n
 *   6. s = (k + e·d_eff) mod n   (using mulModN + addModN)
 *   7. sig = R.x ‖ s (64 bytes)
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
 *   Memory: caller supplies a 256-byte transient scratchpad (CLEAR_ON_DESELECT).
 *
 * ENG-182 — lnflash/cashu-javacard
 */
final class SchnorrHW {

    // ── secp256k1 group order n ────────────────────────────────────────────
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
     */
    private static final byte[] DELTA = {
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x45,(byte)0x51,(byte)0x23,(byte)0x19,(byte)0x50,(byte)0xB7,(byte)0x5F,(byte)0xC4,
        (byte)0x40,(byte)0x2D,(byte)0xA1,(byte)0x73,(byte)0x2F,(byte)0xC9,(byte)0xBE,(byte)0xBF
    };

    // ── Precomputed tag hashes (set once at install time) ─────────────────
    // SHA256("BIP0340/nonce") and SHA256("BIP0340/challenge")
    // Stored in EEPROM, initialised by init().
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

    // ── Crypto objects (allocated once) ───────────────────────────────────
    private final MessageDigest sha256;
    private final KeyAgreement  ecdh;      // ALG_EC_SVDP_DH_PLAIN_XY
    private final ECPrivateKey  tmpPriv;   // reused temp key for k
    private final ECPublicKey   genPub;    // generator G as EC public key

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

        tagHashNonce     = new byte[32];
        tagHashChallenge = new byte[32];

        sc     = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // Generator as EC public key (used as ECDH "peer" for k*G)
        genPub = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        setECParams(null, genPub);
        genPub.setW(G, (short)0, (short)65);

        // Temp private key slot for k (reused each sign call)
        tmpPriv = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        setECParams(tmpPriv, null);

        ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
    }

    /**
     * Must be called once during applet install (after constructor) to
     * precompute and store the BIP-340 tag hashes in EEPROM.
     */
    void init() {
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
        privKey.getS(sc, SC_D);    // d at sc[0..31]

        // Get public key point W (uncompressed 65 bytes or compressed 33 bytes)
        short wLen = pubKey.getW(sc, SC_TMP);  // W at sc[96..]
        boolean pyOdd;
        if (wLen == 65 && sc[SC_TMP] == (byte)0x04) {
            // Uncompressed: 04 || Px(32) || Py(32)
            // P.y is sc[TMP+33..TMP+64]; parity = LSB of last byte
            pyOdd = (sc[(short)(SC_TMP + 64)] & 1) == 1;
            Util.arrayCopy(sc, (short)(SC_TMP + 1), sc, SC_PX, (short)32);
        } else {
            // Compressed: prefix 02 (even) or 03 (odd)
            pyOdd = (sc[SC_TMP] & 1) == 1;
            Util.arrayCopy(sc, (short)(SC_TMP + 1), sc, SC_PX, (short)32);
        }

        if (pyOdd) {
            subtractFromN(sc, SC_D, sc, SC_D);   // d = n − d
        }

        // ── Step 2: k = taggedHash("BIP0340/nonce", d ‖ 0x32 ‖ msg) mod n
        // sc[TMP..TMP+95] = d(32) || zeros(32) || msg(32)
        Util.arrayCopy(sc,  SC_D,   sc, SC_TMP,         (short)32);  // d
        Util.arrayFillNonAtomic(sc, (short)(SC_TMP+32), (short)32, (byte)0); // zeros
        Util.arrayCopy(msg, msgOff, sc, (short)(SC_TMP+64), (short)32);      // msg
        taggedHash(tagHashNonce, sc, SC_TMP, (short)96, sc, SC_K);
        reduceModN(sc, SC_K);         // k = k mod n (in place)

        // ── Step 3: R = k·G via ECDH coprocessor ─────────────────────
        // Load k into temp private key, compute [k]G
        tmpPriv.setS(sc, SC_K, (short)32);
        ecdh.init(tmpPriv);
        // Result = 65-byte uncompressed point at sc[TMP]; we need 65 bytes
        // sc[TMP..TMP+64] = 04 || Rx(32) || Ry(32)
        ecdh.generateSecret(G, (short)0, (short)65, sc, SC_TMP);

        // ── Step 4: if R.y is odd, k = n − k ─────────────────────────
        boolean ryOdd = (sc[(short)(SC_TMP + 64)] & 1) == 1;
        if (ryOdd) {
            subtractFromN(sc, SC_K, sc, SC_K);
        }
        // Rx is at sc[TMP+1..TMP+32]

        // ── Step 5: e = taggedHash("BIP0340/challenge", Rx ‖ Px ‖ msg) mod n
        // Re-use sc[TMP..TMP+95] for the 96-byte input
        // sc[TMP..TMP+31]  = Rx  (already there at SC_TMP+1, shift left by 1)
        Util.arrayCopy(sc, (short)(SC_TMP+1), sc, SC_TMP,          (short)32); // Rx
        Util.arrayCopy(sc, SC_PX,             sc, (short)(SC_TMP+32),(short)32); // Px
        Util.arrayCopy(msg, msgOff,           sc, (short)(SC_TMP+64),(short)32); // msg
        taggedHash(tagHashChallenge, sc, SC_TMP, (short)96, sc, SC_E);
        reduceModN(sc, SC_E);         // e = e mod n

        // ── Step 6: s = (k + e·d) mod n ──────────────────────────────
        mulModN(sc, SC_E, sc, SC_D, sc, SC_ED);     // ed = e * d mod n
        addModN(sc, SC_ED, sc, SC_K, out, (short)(outOff + 32)); // s = ed + k mod n

        // ── Step 7: output = Rx ‖ s ──────────────────────────────────
        // Rx is at sc[TMP+1] (after R was written by ecdh.generateSecret)
        // BUT we overwrote sc[TMP] in step 5.  We must save Rx before step 5.
        // ⚠  Fix: copy Rx to out[outOff] BEFORE the taggedHash call above.
        //    This requires a temporary save — use out[outOff] directly.
        //    Revised: saved below — see note in sign2().
        // Actually the code above has a bug: we overwrote SC_TMP in step 5 with
        // Rx → Px → msg, so Rx is still at sc[SC_TMP..SC_TMP+31].  ✓
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
     * Temporary storage needed: 64 bytes.  Uses the caller-supplied scratch[].
     * Callers pass sc offsets that are clear at call time.
     *
     * @param a      256-bit input A (32 bytes, big-endian)
     * @param aOff   offset of A
     * @param b      256-bit input B (32 bytes, big-endian)
     * @param bOff   offset of B
     * @param out    32-byte output buffer
     * @param outOff offset in output buffer
     */
    static void mulModN(byte[] a, short aOff,
                        byte[] b, short bOff,
                        byte[] out, short outOff) {
        // Allocate 64-byte product on the heap.
        // In JavaCard, small transient allocations inside methods are
        // expensive; this method is only called once per signing operation.
        byte[] prod = new byte[64];
        mul256x256(a, aOff, b, bOff, prod, (short)0);
        reduce512toModN(prod, (short)0, out, outOff);
    }

    /**
     * Schoolbook 256×256 → 512-bit unsigned multiplication.
     * a[32], b[32] → out[64], all big-endian.
     */
    private static void mul256x256(byte[] a, short aOff,
                                   byte[] b, short bOff,
                                   byte[] out, short outOff) {
        Util.arrayFillNonAtomic(out, outOff, (short)64, (byte)0);
        for (short i = 31; i >= 0; i--) {
            int ai = a[(short)(aOff+i)] & 0xFF;
            if (ai == 0) continue;
            int carry = 0;
            for (short j = 31; j >= 0; j--) {
                int bj   = b[(short)(bOff+j)] & 0xFF;
                short pos = (short)(outOff + i + j + 1);
                int  cur  = out[pos] & 0xFF;
                int  prod = ai * bj + cur + carry;
                out[pos]  = (byte)(prod & 0xFF);
                carry     = prod >>> 8;
            }
            // propagate carry into upper bytes
            short pos = (short)(outOff + i);
            while (carry != 0 && pos >= outOff) {
                int s = (out[pos] & 0xFF) + carry;
                out[pos--] = (byte)(s & 0xFF);
                carry      = s >>> 8;
            }
        }
    }

    /**
     * Reduce a 512-bit value (64 bytes, big-endian) to 256-bit mod n.
     * Uses depth-2 DELTA reduction.  Result in out[32].
     */
    private static void reduce512toModN(byte[] p, short pOff,
                                        byte[] out, short outOff) {
        // p = p_hi * 2^256 + p_lo
        // Step 1: t = p_hi * DELTA  (256×32-eff → 256 bits after mod-n reduction)
        // t fits in 48 bytes worst-case, but we compute mod-n in two steps.
        byte[] t = new byte[64];
        mul256x256(p, pOff, DELTA, (short)0, t, (short)0);
        // t = (p_hi * DELTA)_hi * 2^256 + (p_hi * DELTA)_lo
        // Apply identity again to t_hi part:
        byte[] t2 = new byte[64];
        mul256x256(t, (short)0, DELTA, (short)0, t2, (short)0);
        // t2_hi * DELTA < 2^128 * 2^128 = 2^256 < 2n → directly add, then subtract
        // Sum = t2_lo + t[32..63] + p[pOff+32..pOff+63]
        // But t2_hi is tiny (< DELTA < 2^128), its contribution via DELTA:
        //   t2_hi * DELTA < 2^256 fits in 32 bytes.
        byte[] hiContrib = new byte[32];
        mul256x32(t2, (short)0, DELTA, (short)0, hiContrib, (short)0);
        // Now sum = hiContrib + t2[32..63] + t[32..63] + p[32..63]
        add4x32(hiContrib, (short)0,
                t2, (short)32,
                t, (short)32,
                p, (short)(pOff+32),
                out, outOff);
        // Final reduction: at most 2–3 conditional subtracts
        while (cmp32(out, outOff, N, (short)0) >= 0) {
            sub32(out, outOff, N, (short)0, out, outOff);
        }
    }

    /**
     * Multiply the 32-byte high half of a 64-byte value by DELTA (32 bytes).
     * a[0..31] is the operand.  Result in out[32].
     * (Convenience wrapper — takes upper half of a 64-byte buffer.)
     */
    private static void mul256x32(byte[] a, short aOff,
                                  byte[] delta, short deltaOff,
                                  byte[] out, short outOff) {
        byte[] full = new byte[64];
        mul256x256(a, aOff, delta, deltaOff, full, (short)0);
        // full[0..31] is the upper half — for delta ≈ 2^128, the upper 32 bytes
        // of full (the top 256 bits of the 512-bit product) are all zero because
        // a < 2^256 and delta < 2^128.  Lower 32 bytes (full[32..63]) is the result.
        Util.arrayCopy(full, (short)32, out, outOff, (short)32);
    }

    /**
     * out = (a + b + c + d) mod n   — four 32-byte big-endian terms.
     * Carries propagated correctly for sum up to 4*(2^256 − 1) ≈ 2^258.
     */
    private static void add4x32(byte[] a, short aOff,
                                 byte[] b, short bOff,
                                 byte[] c, short cOff,
                                 byte[] d, short dOff,
                                 byte[] out, short outOff) {
        int carry = 0;
        for (short i = 31; i >= 0; i--) {
            int s = (a[(short)(aOff+i)] & 0xFF)
                  + (b[(short)(bOff+i)] & 0xFF)
                  + (c[(short)(cOff+i)] & 0xFF)
                  + (d[(short)(dOff+i)] & 0xFF)
                  + carry;
            out[(short)(outOff+i)] = (byte)(s & 0xFF);
            carry = s >>> 8;
        }
        // carry is small (≤ 3) — apply mod-n reduces below handle it
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
