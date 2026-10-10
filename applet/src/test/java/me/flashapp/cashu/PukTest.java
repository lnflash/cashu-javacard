package me.flashapp.cashu;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javacard.framework.OwnerPIN;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * D16 (ENG-617): SET_PUK and UNBLOCK_PIN, applet 0.6.
 *
 * The PUK is the one credential that takes a PIN off a blocked card. Three
 * things are checked here, in the order they matter:
 *
 * 1. The ENG-615 invariant still holds: a blocked PIN gates every command
 *    until UNBLOCK_PIN succeeds, and nothing else — not CLEAR_PIN, not
 *    SET_PIN, not a wrong PUK — opens it.
 * 2. Who may attach a PUK: anyone on a card with no PIN, only a verified
 *    session on a card with one, nobody on a blocked card, nobody twice.
 * 3. The write orders, scanned in the source as D14's and D15's are, and the
 *    states a tear can leave, set directly and shown to be harmless.
 */
class PukTest {

    // ── the orders, in the source ────────────────────────────────────────────

    @Test
    @DisplayName("SET_PUK commits pukState after the PUK; UNBLOCK_PIN checks the PUK, writes the PIN, then commits pinState, with no redundant counter reset")
    void appletCommitsTheStateBytesLast() throws Exception {
        String src = new String(
            java.nio.file.Files.readAllBytes(
                SchnorrHWMathTest.mainSourceDir().resolve("CashuApplet.java")),
            java.nio.charset.StandardCharsets.UTF_8);
        List<String> violations = pukWriteViolations(src);
        assertTrue(violations.isEmpty(), String.join("\n", violations));
    }

    @Test
    @DisplayName("the scan fails a state-first SET_PUK, an unblock that writes before the check, one that commits before the PIN, a counter reset, and a missing commit")
    void theScanCanSayNo() {
        String setPukGood = " private void processSetPuk(APDU apdu) {"
            + " puk.update(buf, off, pukLen);"
            + " pukState[0] = (byte) 1;"
            + " }";
        String unblockGood = " private void processUnblockPin(APDU apdu) {"
            + " boolean ok = puk.check(buf, pukOff, pukLen);"
            + " if (!ok) failPukCheck();"
            + " pin.update(buf, off, newLen);"
            + " pinState[0] = (byte) 1;"
            + " pinVerifiedFlag[0] = (byte) 0;"
            + " }";
        String failGood = " private void failPukCheck() {"
            + " byte remaining = puk.getTriesRemaining();"
            + " if (remaining == 0) { pukState[0] = (byte) 2; }"
            + " }";

        String stateFirstSetPuk = "class A {"
            + " private void processSetPuk(APDU apdu) {"
            + " pukState[0] = (byte) 1;"
            + " puk.update(buf, off, pukLen);"
            + " }" + unblockGood + failGood + " }";
        String writeBeforeCheck = "class A {" + setPukGood
            + " private void processUnblockPin(APDU apdu) {"
            + " pin.update(buf, off, newLen);"
            + " boolean ok = puk.check(buf, pukOff, pukLen);"
            + " if (!ok) failPukCheck();"
            + " pinState[0] = (byte) 1;"
            + " }" + failGood + " }";
        String commitBeforePin = "class A {" + setPukGood
            + " private void processUnblockPin(APDU apdu) {"
            + " boolean ok = puk.check(buf, pukOff, pukLen);"
            + " if (!ok) failPukCheck();"
            + " pinState[0] = (byte) 1;"
            + " pin.update(buf, off, newLen);"
            + " }" + failGood + " }";
        String counterReset = "class A {" + setPukGood
            + " private void processUnblockPin(APDU apdu) {"
            + " boolean ok = puk.check(buf, pukOff, pukLen);"
            + " if (!ok) failPukCheck();"
            + " pin.resetAndUnblock();"
            + " pin.update(buf, off, newLen);"
            + " pinState[0] = (byte) 1;"
            + " }" + failGood + " }";
        String noCommit = "class A {" + setPukGood
            + " private void processUnblockPin(APDU apdu) {"
            + " boolean ok = puk.check(buf, pukOff, pukLen);"
            + " if (!ok) failPukCheck();"
            + " pin.update(buf, off, newLen);"
            + " }" + failGood + " }";
        String noCheck = "class A {" + setPukGood
            + " private void processUnblockPin(APDU apdu) {"
            + " pin.update(buf, off, newLen);"
            + " pinState[0] = (byte) 1;"
            + " }" + failGood + " }";
        String exhaustedBeforeRead = "class A {" + setPukGood + unblockGood
            + " private void failPukCheck() {"
            + " pukState[0] = (byte) 2;"
            + " byte remaining = puk.getTriesRemaining();"
            + " }" + " }";
        String good = "class A {" + setPukGood + unblockGood + failGood + " }";

        assertFalse(pukWriteViolations(stateFirstSetPuk).isEmpty(), "state-first SET_PUK passed");
        assertFalse(pukWriteViolations(writeBeforeCheck).isEmpty(), "PIN write before the PUK check passed");
        assertFalse(pukWriteViolations(commitBeforePin).isEmpty(), "commit before the PIN write passed");
        assertFalse(pukWriteViolations(counterReset).isEmpty(), "a redundant counter reset passed");
        assertFalse(pukWriteViolations(noCommit).isEmpty(), "an unblock that never commits pinState passed");
        assertFalse(pukWriteViolations(noCheck).isEmpty(), "an unblock without a PUK check passed");
        assertFalse(pukWriteViolations(exhaustedBeforeRead).isEmpty(), "pukState 2 before the counter read passed");
        assertTrue(pukWriteViolations(good).isEmpty(), String.join("\n", pukWriteViolations(good)));
    }

    /** The body of `void NAME(` in comment-stripped source, or null. */
    private static String body(String src, String name) {
        int decl = src.indexOf("void " + name + "(");
        if (decl < 0) return null;
        int open = src.indexOf('{', decl);
        int[] depth = SchnorrHWMathTest.braceDepths(src);
        int close = open;
        while (close < src.length() && !(src.charAt(close) == '}' && depth[close] == depth[open])) close++;
        return src.substring(open, close);
    }

    /**
     * Violations of the D16 write rules:
     * - processSetPuk: puk.update does not precede `pukState[0] = (byte) 1`,
     *   or either is missing;
     * - processUnblockPin: puk.check, pin.update and `pinState[0] = (byte) 1`
     *   are not all present in that order; or pin.resetAndUnblock is called
     *   (OwnerPIN.update already refills the counter — D15's redundant-write
     *   lesson); or a persistent write follows the commit;
     * - failPukCheck: `pukState[0] = (byte) 2` does not follow the counter
     *   read, so a tear could leave the exhausted mark without the decrement
     *   that earned it.
     */
    static List<String> pukWriteViolations(String rawSrc) {
        String src = SchnorrHWMathTest.stripCommentsAndCharLiterals(rawSrc);
        List<String> violations = new ArrayList<>();

        String setPuk = body(src, "processSetPuk");
        if (setPuk == null) {
            violations.add("no processSetPuk in the source");
        } else {
            int update = setPuk.indexOf("puk.update(");
            int state = setPuk.indexOf("pukState[0] = (byte) 1");
            if (update < 0) violations.add("processSetPuk never writes the PUK");
            if (state < 0) violations.add("processSetPuk never sets pukState to 1");
            if (update >= 0 && state >= 0 && state < update) {
                violations.add("processSetPuk commits pukState before the PUK is written: a tear leaves"
                    + " a set PUK nobody knows");
            }
        }

        String unblock = body(src, "processUnblockPin");
        if (unblock == null) {
            violations.add("no processUnblockPin in the source");
        } else {
            int check = unblock.indexOf("puk.check(");
            int update = unblock.indexOf("pin.update(");
            int state = unblock.indexOf("pinState[0] = (byte) 1");
            if (check < 0) violations.add("processUnblockPin never checks the PUK");
            if (update < 0) violations.add("processUnblockPin never writes the new PIN");
            if (state < 0) violations.add("processUnblockPin never commits pinState 1");
            if (check >= 0 && update >= 0 && update < check) {
                violations.add("processUnblockPin writes the PIN before the PUK check: a wrong PUK must"
                    + " change nothing");
            }
            if (update >= 0 && state >= 0 && state < update) {
                violations.add("processUnblockPin commits pinState before the PIN is written: a tear"
                    + " leaves state 1 over the old PIN and its exhausted counter");
            }
            if (unblock.contains("pin.resetAndUnblock()")) {
                violations.add("processUnblockPin resets the try counter: OwnerPIN.update already"
                    + " refills it, and D15 records why a redundant counter write is worse than none");
            }
            if (state >= 0) {
                String after = unblock.substring(state);
                if (after.indexOf("pin.update(") > 0 || after.indexOf("puk.update(") > 0
                        || after.indexOf("pukState[0]") > 0) {
                    violations.add("processUnblockPin writes persistent state after the pinState commit");
                }
            }
        }

        String fail = body(src, "failPukCheck");
        if (fail == null) {
            violations.add("no failPukCheck in the source");
        } else {
            int read = fail.indexOf("puk.getTriesRemaining()");
            int state = fail.indexOf("pukState[0] = (byte) 2");
            if (read < 0) violations.add("failPukCheck never reads the PUK tries");
            if (state < 0) violations.add("failPukCheck never marks the PUK exhausted");
            if (read >= 0 && state >= 0 && state < read) {
                violations.add("failPukCheck marks the PUK exhausted before reading the counter");
            }
        }
        return violations;
    }

    // ── a card with its persistent state exposed ─────────────────────────────

    private static final class ExposedRuntime extends SimulatorRuntime {
        Applet appletAt(AID aid) {
            return getApplet(aid);
        }
    }

    private static final byte CLA = CashuAppletTest.CLA;
    private static final int SW_OK = CashuAppletTest.SW_OK;
    private static final int SW_WRONG_LENGTH = CashuAppletTest.SW_WRONG_LENGTH;
    private static final int SW_SECURITY_NOT_SATIS = CashuAppletTest.SW_SECURITY_NOT_SATIS;
    private static final int SW_PIN_BLOCKED = CashuAppletTest.SW_PIN_BLOCKED;
    private static final int SW_PIN_NOT_SET = CashuAppletTest.SW_PIN_NOT_SET;
    private static final int SW_CONDITIONS_NOT_SATIS = CashuAppletTest.SW_CONDITIONS_NOT_SATIS;
    private static final int SW_COMMAND_NOT_ALLOWED = 0x6986;
    private static final int SW_PUK_NOT_SET = 0x6A82;
    private static final int SW_PUK_ALREADY_SET = 0x6A89;
    private static final int SW_PUK_BLOCKED = 0x6983;

    private static final byte[] TEST_PIN = CashuAppletTest.TEST_PIN;
    private static final byte[] WRONG_PIN = CashuAppletTest.WRONG_PIN;
    private static final byte[] NEW_PIN = CashuAppletTest.NEW_PIN;
    private static final byte[] PUK = "12345678".getBytes();          // 8 digits: the minimum
    private static final byte[] LONG_PUK = "123456789012".getBytes(); // 12 digits: the maximum
    private static final byte[] WRONG_PUK = "00000000".getBytes();

    private CardSimulator sim;
    private byte[] pinState;
    private byte[] pukState;
    private OwnerPIN pin;
    private OwnerPIN puk;

    private void freshCard() throws Exception {
        ExposedRuntime runtime = new ExposedRuntime();
        sim = new CardSimulator(runtime);
        AID aid = AIDUtil.create(CashuAppletTest.AID_HEX);
        sim.installApplet(aid, CashuApplet.class);
        assertEquals(SW_OK, reselect());
        Applet applet = runtime.appletAt(aid);
        pinState = (byte[]) field(applet, "pinState");
        pukState = (byte[]) field(applet, "pukState");
        pin = (OwnerPIN) field(applet, "pin");
        puk = (OwnerPIN) field(applet, "puk");
    }

    private static Object field(Applet applet, String name) throws Exception {
        java.lang.reflect.Field f = CashuApplet.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(applet);
    }

    private int reselect() {
        return sim.transmitCommand(new CommandAPDU(
            0x00, 0xA4, 0x04, 0x00, CashuAppletTest.hexToBytes(CashuAppletTest.AID_STR))).getSW();
    }

    private int send(int ins, byte[] data) {
        return sim.transmitCommand(new CommandAPDU(CLA, ins, 0, 0, data)).getSW();
    }

    /** SET_PUK data: 1-byte PUK length, PUK — CLEAR_PIN's framing. */
    static byte[] setPukData(byte[] puk) {
        byte[] data = new byte[1 + puk.length];
        data[0] = (byte) puk.length;
        System.arraycopy(puk, 0, data, 1, puk.length);
        return data;
    }

    /** UNBLOCK_PIN data: 1-byte PUK length, PUK, 1-byte new PIN length, new PIN. */
    static byte[] unblockData(byte[] puk, byte[] newPin) {
        byte[] data = new byte[2 + puk.length + newPin.length];
        data[0] = (byte) puk.length;
        System.arraycopy(puk, 0, data, 1, puk.length);
        data[1 + puk.length] = (byte) newPin.length;
        System.arraycopy(newPin, 0, data, 2 + puk.length, newPin.length);
        return data;
    }

    private int setPuk(byte[] puk) {
        return send(CashuAppletTest.INS_SET_PUK, setPukData(puk));
    }

    private int unblock(byte[] puk, byte[] newPin) {
        return send(CashuAppletTest.INS_UNBLOCK_PIN, unblockData(puk, newPin));
    }

    private int setPin(byte[] pin) {
        return send(CashuAppletTest.INS_SET_PIN, pin);
    }

    private int verify(byte[] pin) {
        return send(CashuAppletTest.INS_VERIFY_PIN, pin);
    }

    private int clearPin(byte[] pin) {
        return send(CashuAppletTest.INS_CLEAR_PIN, CashuAppletTest.clearPinData(pin));
    }

    private int loadProof1() {
        return sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_LOAD_PROOF, 0, 0,
            CashuAppletTest.PROOF_1, 0, CashuAppletTest.PROOF_1.length, 1)).getSW();
    }

    private int spend(int slot) {
        return sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_SPEND_PROOF, slot, 0,
            new byte[32], 64)).getSW();
    }

    private int sign() {
        return sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_SIGN_ARBITRARY, 0, 0,
            new byte[32], 64)).getSW();
    }

    private int lock() {
        return sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_LOCK_CARD, 0, 0xDE)).getSW();
    }

    private byte[] info() {
        ResponseAPDU r = sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_GET_INFO, 0, 0, 256));
        assertEquals(SW_OK, r.getSW());
        return r.getData();
    }

    private int infoPinState() {
        return info()[7] & 0xFF;
    }

    private int infoPukState() {
        return info()[8] & 0xFF;
    }

    /** Three wrong VERIFY_PINs: the unauthenticated block any reader in range can send. */
    private void blockThePin() {
        assertEquals(0x63C2, verify(WRONG_PIN));
        assertEquals(0x63C1, verify(WRONG_PIN));
        assertEquals(SW_PIN_BLOCKED, verify(WRONG_PIN));
        assertEquals(2, infoPinState(), "the PIN is blocked");
    }

    private void assertGatedCommandsRefuse(String when) {
        assertEquals(SW_SECURITY_NOT_SATIS, spend(0), "SPEND_PROOF " + when);
        assertEquals(0x01,
            sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_GET_PROOF, 0, 0, 78)).getData()[0] & 0xFF,
            "the slot is intact " + when + ": the gate ran before the burn");
        assertEquals(SW_SECURITY_NOT_SATIS, sign(), "SIGN_ARBITRARY " + when);
        assertEquals(SW_SECURITY_NOT_SATIS,
            sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_LOAD_PROOF, 0, 0,
                CashuAppletTest.PROOF_2, 0, CashuAppletTest.PROOF_2.length, 1)).getSW(),
            "LOAD_PROOF " + when);
        assertEquals(SW_SECURITY_NOT_SATIS,
            sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_CLEAR_SPENT, 0, 0, 1)).getSW(),
            "CLEAR_SPENT " + when);
        assertEquals(SW_SECURITY_NOT_SATIS, lock(), "LOCK_CARD " + when);
        assertEquals(SW_SECURITY_NOT_SATIS, clearPin(TEST_PIN), "CLEAR_PIN " + when);
        assertEquals(SW_CONDITIONS_NOT_SATIS, setPin(NEW_PIN), "SET_PIN " + when);
    }

    // ── GET_INFO ─────────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET_INFO is 9 bytes: version 0.6, capabilities 0x1F, and byte 8 is the PUK state 0 / 1 / 2")
    void getInfoReportsTheVersionTheCapabilityAndThePukState() throws Exception {
        freshCard();
        byte[] d = info();
        assertEquals(9, d.length, "eight bytes before 0.6; the PUK state is appended, never inserted");
        assertEquals(0x00, d[0] & 0xFF, "major version");
        assertEquals(0x06, d[1] & 0xFF, "minor version: 0.6 is the first build with SET_PUK and UNBLOCK_PIN");
        assertEquals(0x1F, d[6] & 0xFF, "capability bit 4 says the card answers SET_PUK and UNBLOCK_PIN");
        assertEquals(0, d[7] & 0xFF, "no PIN");
        assertEquals(0, d[8] & 0xFF, "no PUK");

        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(1, infoPukState(), "PUK set");
        assertEquals(0, infoPinState(), "the PIN state is the PIN's, untouched by SET_PUK");

        // Exhaust it: a PIN is needed for UNBLOCK_PIN to reach the check.
        assertEquals(SW_OK, setPin(TEST_PIN));
        for (int i = 9; i >= 0; i--) {
            assertEquals(0x63C0 | i, unblock(WRONG_PUK, NEW_PIN), "wrong PUK, " + i + " tries left");
        }
        assertEquals(2, infoPukState(), "PUK exhausted");
        assertEquals(1, infoPinState(), "the PIN is still set; a wrong PUK never touches it");
        assertEquals(9, info().length);
    }

    // ── SET_PUK ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("SET_PUK on a card with no PIN needs nothing, works once, and refuses a second PUK (D16)")
    void setPukWorksOnceOnAFreshCard() throws Exception {
        freshCard();
        assertEquals(SW_OK, setPuk(PUK), "SET_PUK first, SET_PIN second: the personalisation order");
        assertEquals(1, infoPukState());
        assertEquals(SW_PUK_ALREADY_SET, setPuk(LONG_PUK), "a PUK is set once");
        assertEquals(SW_PUK_ALREADY_SET, setPuk(PUK), "even to the same value");
        assertEquals(1, infoPukState());

        // The PUK that was set is the one that works, and it survives the
        // card gaining a PIN.
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(0x63C9, unblock(LONG_PUK, NEW_PIN), "the refused second PUK was never stored");
        assertEquals(SW_OK, unblock(PUK, NEW_PIN), "the first PUK is the card's PUK");
    }

    @Test
    @DisplayName("a 12-digit PUK is accepted at the top of the range and drives UNBLOCK_PIN")
    void aMaximumLengthPukWorks() throws Exception {
        freshCard();
        assertEquals(SW_OK, setPuk(LONG_PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        blockThePin();
        assertEquals(SW_OK, unblock(LONG_PUK, NEW_PIN));
        assertEquals(1, infoPinState());
        assertEquals(SW_OK, verify(NEW_PIN));
    }

    @Test
    @DisplayName("SET_PUK on a PIN card needs a verified session: 6982 without VERIFY_PIN, 9000 with (D16)")
    void setPukOnAPinCardNeedsTheHoldersSession() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPin(TEST_PIN));

        // The other personalisation order: SET_PIN, VERIFY_PIN, SET_PUK. A
        // reader in range must not be able to attach a PUK of its own behind
        // the holder's back — that PUK would be a PIN bypass for this card.
        assertEquals(SW_SECURITY_NOT_SATIS, setPuk(PUK), "SET_PUK without VERIFY_PIN");
        assertEquals(0, infoPukState(), "nothing was attached");
        assertEquals(0x63C2, verify(WRONG_PIN), "and the refused SET_PUK cost no PIN try");
        assertEquals(SW_SECURITY_NOT_SATIS, setPuk(PUK), "a failed check is not a session");

        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setPuk(PUK), "SET_PUK in the holder's session");
        assertEquals(1, infoPukState());
        assertEquals(SW_OK, spend(0), "the session is still verified: SET_PUK does not end it");
    }

    @Test
    @DisplayName("SET_PUK on a blocked card is 6982 in every session: the reader that blocked it cannot arm its own recovery (D16, ENG-615)")
    void setPukOnABlockedCardIsRefusedForGood() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPin(TEST_PIN));
        blockThePin();

        assertEquals(SW_SECURITY_NOT_SATIS, setPuk(PUK), "SET_PUK on a blocked card");
        assertEquals(0, infoPukState());
        assertEquals(SW_OK, reselect());
        assertEquals(SW_SECURITY_NOT_SATIS, setPuk(PUK), "in the next session too");
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN), "VERIFY_PIN cannot open one");
        assertEquals(SW_SECURITY_NOT_SATIS, setPuk(PUK), "SET_PUK after that");
        assertEquals(0, infoPukState());
        // And with no PUK there is no way out: the card is as 0.5 left it.
        assertEquals(SW_PUK_NOT_SET, unblock(PUK, NEW_PIN));
        assertEquals(2, infoPinState());
        assertGatedCommandsRefuse("on a blocked card with no PUK");
    }

    @Test
    @DisplayName("SET_PUK with a bad length is 6700 and stores nothing (D16)")
    void setPukWrongLength() throws Exception {
        freshCard();
        assertEquals(SW_WRONG_LENGTH, send(CashuAppletTest.INS_SET_PUK, new byte[0]), "no data");
        assertEquals(SW_WRONG_LENGTH, send(CashuAppletTest.INS_SET_PUK, setPukData("1234567".getBytes())),
            "PUK length 7");
        assertEquals(SW_WRONG_LENGTH, send(CashuAppletTest.INS_SET_PUK, setPukData("1234567890123".getBytes())),
            "PUK length 13");
        byte[] stray = new byte[1 + PUK.length + 1];
        System.arraycopy(setPukData(PUK), 0, stray, 0, 1 + PUK.length);
        assertEquals(SW_WRONG_LENGTH, send(CashuAppletTest.INS_SET_PUK, stray), "a byte after the PUK");
        byte[] truncated = { (byte) PUK.length, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 };
        assertEquals(SW_WRONG_LENGTH, send(CashuAppletTest.INS_SET_PUK, truncated),
            "a PUK shorter than its length byte");
        assertEquals(0, infoPukState(), "none of that stored a PUK");
        assertEquals(SW_OK, setPuk(PUK), "and SET_PUK is still open");
    }

    // ── UNBLOCK_PIN: the gates ───────────────────────────────────────────────

    @Test
    @DisplayName("UNBLOCK_PIN without a PUK is 6A82 on a PIN card and on a blocked card, and changes nothing (D16)")
    void unblockWithoutAPukIsRefused() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_PUK_NOT_SET, unblock(PUK, NEW_PIN), "no PIN and no PUK: the PUK gate answers first");
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_PUK_NOT_SET, unblock(PUK, NEW_PIN), "a PIN card with no PUK");
        assertEquals(1, infoPinState());
        assertEquals(SW_OK, verify(TEST_PIN), "the PIN is untouched");
        blockThePin();
        assertEquals(SW_PUK_NOT_SET, unblock(PUK, NEW_PIN), "a blocked card with no PUK");
        assertEquals(2, infoPinState(), "still blocked");
        assertGatedCommandsRefuse("after UNBLOCK_PIN on a card with no PUK");
    }

    @Test
    @DisplayName("UNBLOCK_PIN on a card with no PIN is 6984 and costs no PUK try: there is nothing to unblock, SET_PIN is the way (D16)")
    void unblockOnANoPinCardIsRefused() throws Exception {
        freshCard();
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_PIN_NOT_SET, unblock(PUK, NEW_PIN), "the right PUK on a card with no PIN");
        assertEquals(SW_PIN_NOT_SET, unblock(WRONG_PUK, NEW_PIN), "and a wrong one is never checked");
        assertEquals(0, infoPinState(), "no PIN appeared");
        assertEquals(1, infoPukState());
        assertEquals(SW_PIN_NOT_SET, verify(NEW_PIN));

        // The PUK counter is whole: the first real wrong PUK is 63C9.
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(0x63C9, unblock(WRONG_PUK, NEW_PIN), "ten tries, none spent on the refusals");
    }

    @Test
    @DisplayName("a wrong PUK counts down 63C9…63C0, the tenth exhausts it (GET_INFO byte 8 = 2), and the right PUK is 6983 for good; the PIN is untouched throughout (D16)")
    void aWrongPukCountsDownAndTheTenthIsTerminal() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));

        for (int i = 9; i >= 1; i--) {
            assertEquals(0x63C0 | i, unblock(WRONG_PUK, NEW_PIN), i + " PUK tries left");
            assertEquals(1, infoPukState(), "still set with " + i + " left");
            assertEquals(1, infoPinState());
        }
        assertEquals(0x63C0, unblock(WRONG_PUK, NEW_PIN), "the exhausting try reports zero left");
        assertEquals(2, infoPukState(), "and the PUK is exhausted");

        // Terminal: the right PUK no longer helps, in this session or the
        // next, and no new PUK can be attached.
        assertEquals(SW_PUK_BLOCKED, unblock(PUK, NEW_PIN), "the right PUK on an exhausted card");
        assertEquals(SW_OK, reselect());
        assertEquals(SW_PUK_BLOCKED, unblock(PUK, NEW_PIN), "in the next session");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_PUK_ALREADY_SET, setPuk(LONG_PUK), "exhausted is not unset: the holder cannot re-arm it");
        assertEquals(2, infoPukState());

        // The PIN never noticed: still the same PIN, still three tries.
        assertEquals(SW_OK, sign(), "the holder's session signs");
        assertEquals(0x63C2, verify(WRONG_PIN), "three PIN tries, none spent by the PUK guesses");
        assertEquals(SW_OK, verify(TEST_PIN));

        // Once blocked now, the card is stranded as a 0.5 card is: the
        // exhausted PUK is as good as none.
        blockThePin();
        assertEquals(SW_PUK_BLOCKED, unblock(PUK, NEW_PIN));
        assertGatedCommandsRefuse("on a blocked card whose PUK is exhausted");
    }

    @Test
    @DisplayName("a wrong PUK ends the session's PIN verification, as every failed check does (D16)")
    void aWrongPukEndsTheSession() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, sign(), "verified");

        assertEquals(0x63C9, unblock(WRONG_PUK, NEW_PIN));
        assertGatedCommandsRefuse("after a wrong PUK");
        assertEquals(1, infoPinState(), "the PIN is still set");
        assertEquals(0x63C2, verify(WRONG_PIN), "and its counter is whole: the PUK failure is the PUK's");
        assertEquals(SW_OK, verify(TEST_PIN), "the same PIN opens a new session");
    }

    @Test
    @DisplayName("UNBLOCK_PIN with a bad length is 6700, costs no PUK try, and checks nothing (D16)")
    void unblockWrongLength() throws Exception {
        freshCard();
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));

        int ins = CashuAppletTest.INS_UNBLOCK_PIN;
        assertEquals(SW_WRONG_LENGTH, send(ins, new byte[0]), "no data");
        assertEquals(SW_WRONG_LENGTH, send(ins, new byte[] { 8 }), "a PUK length and nothing else");
        assertEquals(SW_WRONG_LENGTH, send(ins, unblockData("1234567".getBytes(), NEW_PIN)), "PUK length 7");
        assertEquals(SW_WRONG_LENGTH, send(ins, unblockData("1234567890123".getBytes(), NEW_PIN)), "PUK length 13");
        assertEquals(SW_WRONG_LENGTH, send(ins, unblockData(PUK, "123".getBytes())), "new PIN length 3");
        assertEquals(SW_WRONG_LENGTH, send(ins, unblockData(PUK, "123456789".getBytes())), "new PIN length 9");
        byte[] stray = new byte[2 + PUK.length + NEW_PIN.length + 1];
        System.arraycopy(unblockData(PUK, NEW_PIN), 0, stray, 0, stray.length - 1);
        assertEquals(SW_WRONG_LENGTH, send(ins, stray), "a byte after the new PIN");
        byte[] good = unblockData(PUK, NEW_PIN);
        byte[] truncated = new byte[good.length - 1];
        System.arraycopy(good, 0, truncated, 0, truncated.length);
        assertEquals(SW_WRONG_LENGTH, send(ins, truncated), "a new PIN shorter than its length byte");
        byte[] pukOnly = new byte[1 + PUK.length];
        System.arraycopy(good, 0, pukOnly, 0, pukOnly.length);
        assertEquals(SW_WRONG_LENGTH, send(ins, pukOnly), "a PUK with no new PIN length byte");

        // Wrong PUK in a well-formed command is the first check that ran,
        // and the verified session was still open until it.
        assertEquals(1, infoPinState());
        assertEquals(SW_OK, sign(), "the session survived every 6700");
        assertEquals(0x63C9, unblock(WRONG_PUK, NEW_PIN), "ten PUK tries, none spent on a 6700");
        assertEquals(SW_OK, verify(TEST_PIN), "and the old PIN is still the PIN");
    }

    // ── UNBLOCK_PIN: the point ───────────────────────────────────────────────

    @Test
    @DisplayName("a blocked PIN gates everything until UNBLOCK_PIN with the right PUK; then the old PIN is gone, the new one spends, and the counter is back to 3 (D16, ENG-615)")
    void aBlockedPinIsRecoveredByThePukAndNothingElse() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        blockThePin();
        assertGatedCommandsRefuse("on the blocked card");
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN), "the right PIN cannot open it");

        // A wrong PUK leaves the card exactly as blocked.
        assertEquals(0x63C9, unblock(WRONG_PUK, NEW_PIN));
        assertEquals(2, infoPinState());
        assertGatedCommandsRefuse("after a wrong PUK on the blocked card");

        // The right PUK with a new PIN. No session is needed, and none opens.
        assertEquals(SW_OK, unblock(PUK, NEW_PIN));
        assertEquals(1, infoPinState(), "the PIN is set again");
        assertEquals(1, infoPukState(), "the PUK is not consumed by a successful unblock");
        assertEquals(CashuApplet.PIN_MAX_TRIES, pin.getTriesRemaining(), "three tries, from OwnerPIN.update");
        assertGatedCommandsRefuse("right after the unblock: the PUK proved itself, not the new PIN");

        // The old PIN is gone; the new one works; the counter is fresh.
        assertEquals(0x63C2, verify(TEST_PIN), "the old PIN is refused, at the top of the counter");
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, spend(0), "the new PIN spends");
        assertEquals(SW_OK, sign());

        // And it can happen again: block the new PIN, unblock with the same PUK.
        assertEquals(SW_OK, reselect());
        blockThePin();
        assertEquals(SW_OK, unblock(PUK, TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(1, infoPukState());
    }

    @Test
    @DisplayName("UNBLOCK_PIN on a card whose PIN is set, not blocked, replaces the PIN: a forgotten PIN is the same operation (D16)")
    void unblockReplacesAPinThatIsNotBlocked() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));

        assertEquals(SW_OK, unblock(PUK, NEW_PIN), "state 1 to state 1, with the new PIN");
        assertEquals(1, infoPinState());
        assertEquals(0x63C2, verify(TEST_PIN), "the old PIN is refused");
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, spend(0));

        // In a verified session the replacement ends it: the session verified
        // a PIN that no longer exists, as after CLEAR_PIN.
        assertEquals(SW_OK, unblock(PUK, TEST_PIN));
        assertEquals(SW_SECURITY_NOT_SATIS, sign(), "the session ended with the PIN it verified");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, sign());
    }

    @Test
    @DisplayName("CLEAR_PIN leaves the PUK alone: after CLEAR_PIN then SET_PIN the original PUK still unblocks (D16)")
    void thePukSurvivesClearPinAndSetPin() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, clearPin(TEST_PIN));
        assertEquals(0, infoPinState());
        assertEquals(1, infoPukState(), "CLEAR_PIN removed the PIN, not the PUK");
        assertEquals(SW_PUK_ALREADY_SET, setPuk(LONG_PUK), "and the PUK is still set once");
        assertEquals(SW_PIN_NOT_SET, unblock(PUK, NEW_PIN), "nothing to unblock on a no-PIN card");

        assertEquals(SW_OK, setPin(NEW_PIN));
        blockThePin();
        assertEquals(SW_OK, unblock(PUK, TEST_PIN), "the original PUK unblocks the second PIN");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, spend(0));
    }

    @Test
    @DisplayName("after LOCK_CARD both SET_PUK and UNBLOCK_PIN are 6986: a locked card keeps the PIN and the PUK it has, blocked or not (D16)")
    void lockedCardRefusesBothCommands() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, lock());

        assertEquals(SW_COMMAND_NOT_ALLOWED, setPuk(PUK), "SET_PUK in the verified session that locked the card");
        assertEquals(0, infoPukState());
        assertEquals(SW_COMMAND_NOT_ALLOWED, unblock(PUK, NEW_PIN), "UNBLOCK_PIN, before the PUK gate");

        // A card locked with a PUK already on it: UNBLOCK_PIN is refused by
        // the lock, before the PUK is checked, so no try is spent and a
        // blocked PIN on a locked card stays blocked. LOCK_CARD is the
        // holder's irreversible choice (spec); the PUK does not override it.
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, lock());
        assertEquals(SW_COMMAND_NOT_ALLOWED, unblock(PUK, NEW_PIN), "the right PUK on a locked card");
        assertEquals(SW_COMMAND_NOT_ALLOWED, unblock(WRONG_PUK, NEW_PIN), "a wrong one is never checked");
        assertEquals(CashuApplet.PUK_MAX_TRIES, puk.getTriesRemaining(), "no PUK try spent");
        assertEquals(SW_OK, spend(0), "a locked card still spends in its verified session");
        blockThePin();
        assertEquals(SW_COMMAND_NOT_ALLOWED, unblock(PUK, NEW_PIN), "locked and blocked: 6986, not a recovery");
        assertEquals(2, infoPinState());
    }

    // ── the states a tear can leave ──────────────────────────────────────────

    @Test
    @DisplayName("an UNBLOCK_PIN torn before its commit leaves state 2 over a fresh PIN: VERIFY_PIN is 6983 on the state byte alone, every gate holds, and the next UNBLOCK_PIN finishes it (D16, D14)")
    void aTornUnblockStaysBlockedUntilFinished() throws Exception {
        freshCard();
        assertEquals(SW_OK, loadProof1());
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        blockThePin();

        // What UNBLOCK_PIN leaves when the card goes between pin.update and
        // the state byte: the new PIN is in with its counter at the limit,
        // and pinState still says 2.
        pin.update(NEW_PIN, (short) 0, (byte) NEW_PIN.length);
        assertEquals(CashuApplet.PIN_MAX_TRIES, pin.getTriesRemaining());
        assertEquals(2, pinState[0]);

        assertEquals(2, infoPinState(), "GET_INFO reports blocked");
        assertEquals(SW_PIN_BLOCKED, verify(NEW_PIN), "the new PIN does not verify: state 2 refuses on its own");
        assertEquals(SW_PIN_BLOCKED, verify(TEST_PIN), "nor the old one");
        assertEquals(CashuApplet.PIN_MAX_TRIES, pin.getTriesRemaining(), "and no try was spent: the check never ran");
        assertGatedCommandsRefuse("on the torn card");
        assertEquals(SW_PUK_ALREADY_SET, setPuk(LONG_PUK),
            "no second PUK can be attached to it either (the PUK gate answers before the session gate)");

        // The same PUK finishes the job.
        assertEquals(SW_OK, unblock(PUK, NEW_PIN));
        assertEquals(1, infoPinState());
        assertEquals(SW_OK, verify(NEW_PIN));
        assertEquals(SW_OK, spend(0));
    }

    @Test
    @DisplayName("a SET_PUK torn before its commit leaves a PUK nobody reads: UNBLOCK_PIN is 6A82 and the next SET_PUK overwrites it (D16, D14)")
    void aTornSetPukIsNoPuk() throws Exception {
        freshCard();
        assertEquals(SW_OK, setPin(TEST_PIN));
        // What SET_PUK leaves when the card goes between puk.update and the
        // state byte.
        puk.update(PUK, (short) 0, (byte) PUK.length);
        assertEquals(0, pukState[0]);

        assertEquals(0, infoPukState(), "GET_INFO reports no PUK");
        assertEquals(SW_PUK_NOT_SET, unblock(PUK, NEW_PIN), "the torn PUK is never checked");
        assertEquals(SW_OK, verify(TEST_PIN));
        assertEquals(SW_OK, setPuk(LONG_PUK), "SET_PUK is still open and takes a different PUK");
        assertEquals(1, infoPukState());
        assertEquals(0x63C9, unblock(PUK, NEW_PIN), "the torn value is gone");
        assertEquals(SW_OK, unblock(LONG_PUK, NEW_PIN), "the committed one works");
    }

    @Test
    @DisplayName("a failPukCheck torn before pukState 2 leaves state 1 over a counter at zero: the next UNBLOCK_PIN answers 63C0 and writes the 2, never a recovered try (D16)")
    void aTornExhaustionIsFinishedByTheNextTry() throws Exception {
        freshCard();
        assertEquals(SW_OK, setPuk(PUK));
        assertEquals(SW_OK, setPin(TEST_PIN));
        // Run the OwnerPIN itself to zero, as ten wrong UNBLOCK_PINs do, but
        // without the applet writing the state byte after the last one.
        for (int i = 0; i < CashuApplet.PUK_MAX_TRIES; i++) {
            assertFalse(puk.check(WRONG_PUK, (short) 0, (byte) WRONG_PUK.length));
        }
        assertEquals(0, puk.getTriesRemaining());
        assertEquals(1, pukState[0]);

        assertEquals(1, infoPukState(), "GET_INFO still says set");
        assertEquals(0x63C0, unblock(PUK, NEW_PIN), "the right PUK fails on an empty counter and reports zero");
        assertEquals(2, infoPukState(), "and the state byte catches up");
        assertEquals(SW_PUK_BLOCKED, unblock(PUK, NEW_PIN), "from here it is 6983");
        assertEquals(1, infoPinState(), "the PIN was never touched");
        assertEquals(SW_OK, verify(TEST_PIN));
    }
}
