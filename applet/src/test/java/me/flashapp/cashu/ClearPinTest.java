package me.flashapp.cashu;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Applet;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * D15: CLEAR_PIN's write survives the card leaving the field mid-command.
 *
 * CLEAR_PIN writes two things: pinState to 0, and the OwnerPIN's try counter
 * back to its limit. Written in that order, a tear between them leaves state
 * 0 with a stale counter, which nothing reads: VERIFY_PIN answers 6984 in
 * state 0, and the next SET_PIN's OwnerPIN.update resets the counter with the
 * new PIN. Written the other way round, a tear leaves state 1 with three
 * fresh tries on a PIN the holder still has — a counter reset no command
 * grants, handed out by a pulled card. The pair sits in a JCSystem
 * transaction, but the JavaCard API lets an OwnerPIN keep its internal state
 * outside one, so the order is the guarantee and the transaction is the
 * belt.
 *
 * jCardSim cannot tear a write or roll back a transaction, so this is checked
 * as D14's order is: the order is scanned in the source, and the state a
 * tear can now leave is set on the card directly and shown to be harmless.
 */
class ClearPinTest {

    // ── the order, in the source ─────────────────────────────────────────────

    @Test
    @DisplayName("CLEAR_PIN sets pinState 0 before it resets the counter, inside one transaction, after the PIN check")
    void appletClearsTheStateBeforeTheCounter() throws Exception {
        String src = new String(
            java.nio.file.Files.readAllBytes(
                SchnorrHWMathTest.mainSourceDir().resolve("CashuApplet.java")),
            java.nio.charset.StandardCharsets.UTF_8);
        List<String> violations = clearPinViolations(src);
        assertTrue(violations.isEmpty(), String.join("\n", violations));
    }

    @Test
    @DisplayName("the scan fails a counter-first clear, a clear outside a transaction, and a write before the check")
    void theScanCanSayNo() {
        String counterFirst = "class A { private void processClearPin(APDU apdu) {"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " JCSystem.beginTransaction();"
            + " pin.resetAndUnblock();"
            + " pinState[0] = (byte) 0;"
            + " JCSystem.commitTransaction();"
            + " } }";
        String noTransaction = "class A { private void processClearPin(APDU apdu) {"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " pinState[0] = (byte) 0;"
            + " pin.resetAndUnblock();"
            + " } }";
        String beforeCheck = "class A { private void processClearPin(APDU apdu) {"
            + " JCSystem.beginTransaction();"
            + " pinState[0] = (byte) 0;"
            + " pin.resetAndUnblock();"
            + " JCSystem.commitTransaction();"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " } }";
        String noReset = "class A { private void processClearPin(APDU apdu) {"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " JCSystem.beginTransaction();"
            + " pinState[0] = (byte) 0;"
            + " JCSystem.commitTransaction();"
            + " } }";
        String good = "class A { private void processClearPin(APDU apdu) {"
            + " requireNotLocked(); requirePinVerified();"
            + " boolean ok = pin.check(buf, off, pinLen);"
            + " if (!ok) failPinCheck();"
            + " JCSystem.beginTransaction();"
            + " pinState[0] = (byte) 0;"
            + " pin.resetAndUnblock();"
            + " JCSystem.commitTransaction();"
            + " pinVerifiedFlag[0] = (byte) 0;"
            + " } }";

        assertFalse(clearPinViolations(counterFirst).isEmpty(), "counter-first clear passed");
        assertFalse(clearPinViolations(noTransaction).isEmpty(), "clear outside a transaction passed");
        assertFalse(clearPinViolations(beforeCheck).isEmpty(), "write before the PIN check passed");
        assertFalse(clearPinViolations(noReset).isEmpty(), "clear without a counter reset passed");
        assertTrue(clearPinViolations(good).isEmpty(), String.join("\n", clearPinViolations(good)));
    }

    /**
     * Violations of the CLEAR_PIN write rule in processClearPin:
     * - the PIN check (pin.check) does not precede every write;
     * - pinState is not set to 0 before pin.resetAndUnblock();
     * - either write sits outside JCSystem.beginTransaction()/commitTransaction();
     * - the counter is not reset at all, so a later SET_PIN would inherit
     *   whatever tries the cleared PIN had left — harmless today because
     *   OwnerPIN.update resets it, but the clear is meant to leave the card as
     *   SET_PIN found it, and the scan says so.
     */
    static List<String> clearPinViolations(String rawSrc) {
        String src = SchnorrHWMathTest.stripCommentsAndCharLiterals(rawSrc);
        List<String> violations = new ArrayList<>();
        int decl = src.indexOf("void processClearPin(");
        if (decl < 0) {
            violations.add("no processClearPin in the source");
            return violations;
        }
        int open = src.indexOf('{', decl);
        int[] depth = SchnorrHWMathTest.braceDepths(src);
        int close = open;
        while (close < src.length() && !(src.charAt(close) == '}' && depth[close] == depth[open])) close++;
        String body = src.substring(open, close);

        int check = body.indexOf("pin.check(");
        int begin = body.indexOf("JCSystem.beginTransaction()");
        int state = body.indexOf("pinState[0] = (byte) 0");
        int reset = body.indexOf("pin.resetAndUnblock()");
        int commit = body.indexOf("JCSystem.commitTransaction()");

        if (check < 0) violations.add("processClearPin never checks the PIN");
        if (state < 0) violations.add("processClearPin never sets pinState to 0");
        if (reset < 0) violations.add("processClearPin never resets the try counter (pin.resetAndUnblock)");
        if (begin < 0 || commit < 0) violations.add("processClearPin's writes are not in a JCSystem transaction");
        if (!violations.isEmpty()) return violations;

        if (check > state || check > reset) {
            violations.add("processClearPin writes before the PIN check: a wrong PIN must change nothing");
        }
        if (state > reset) {
            violations.add("processClearPin resets the counter before it clears pinState: a tear between"
                + " them leaves state 1 with fresh tries on a PIN the holder still has");
        }
        if (!(begin < state && state < commit) || !(begin < reset && reset < commit)) {
            violations.add("processClearPin writes outside the transaction: begin at " + begin
                + ", pinState at " + state + ", reset at " + reset + ", commit at " + commit);
        }
        return violations;
    }

    // ── the state a tear can now leave ───────────────────────────────────────

    /** A runtime that hands the test its applet, so pinState can be set to what a tear leaves. */
    private static final class ExposedRuntime extends SimulatorRuntime {
        Applet appletAt(AID aid) {
            return getApplet(aid);
        }
    }

    private static final byte CLA = CashuAppletTest.CLA;
    private CardSimulator sim;
    private byte[] pinState;

    private void freshCard() throws Exception {
        ExposedRuntime runtime = new ExposedRuntime();
        sim = new CardSimulator(runtime);
        AID aid = AIDUtil.create(CashuAppletTest.AID_HEX);
        sim.installApplet(aid, CashuApplet.class);
        assertEquals(CashuAppletTest.SW_OK, sim.transmitCommand(new CommandAPDU(
            0x00, 0xA4, 0x04, 0x00, CashuAppletTest.hexToBytes(CashuAppletTest.AID_STR))).getSW());
        java.lang.reflect.Field field = CashuApplet.class.getDeclaredField("pinState");
        field.setAccessible(true);
        pinState = (byte[]) field.get(runtime.appletAt(aid));
    }

    private int send(int ins, byte[] data) {
        return sim.transmitCommand(new CommandAPDU(CLA, ins, 0, 0, data)).getSW();
    }

    private int verify(byte[] pin) {
        return send(CashuAppletTest.INS_VERIFY_PIN, pin);
    }

    private int infoPinState() {
        ResponseAPDU info = sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_GET_INFO, 0, 0, 256));
        return info.getData()[7] & 0xFF;
    }

    @Test
    @DisplayName("a CLEAR_PIN torn after the state write leaves a no-PIN card with a stale counter, which nothing reads: VERIFY_PIN is 6984, spending is open, and SET_PIN starts the counter fresh")
    void aTornClearLeavesANoPinCardWhoseStaleCounterIsNeverRead() throws Exception {
        freshCard();
        assertEquals(CashuAppletTest.SW_OK,
            send(CashuAppletTest.INS_LOAD_PROOF, CashuAppletTest.PROOF_1));
        assertEquals(CashuAppletTest.SW_OK, send(CashuAppletTest.INS_SET_PIN, CashuAppletTest.TEST_PIN));

        // Run the counter down to one try, then open a session: the VERIFY_PIN
        // that succeeds resets it, so to leave a *stale* counter behind the
        // tear the two wrong tries come after the right one. The session is
        // then over (failPinCheck), which is the one thing this torn state
        // cannot model: a real CLEAR_PIN runs in a verified session. What the
        // card is left holding is the same either way.
        assertEquals(CashuAppletTest.SW_OK, verify(CashuAppletTest.TEST_PIN));
        assertEquals(0x63C2, verify(CashuAppletTest.WRONG_PIN));
        assertEquals(0x63C1, verify(CashuAppletTest.WRONG_PIN));

        // What CLEAR_PIN leaves when the card goes between its two writes:
        // pinState 0, the OwnerPIN still at one try remaining.
        pinState[0] = 0;

        assertEquals(0, infoPinState(), "GET_INFO reports no PIN");
        assertEquals(CashuAppletTest.SW_PIN_NOT_SET, verify(CashuAppletTest.TEST_PIN),
            "VERIFY_PIN has nothing to verify, whatever the counter says");
        assertEquals(CashuAppletTest.SW_PIN_NOT_SET, verify(CashuAppletTest.WRONG_PIN),
            "and a wrong PIN cannot run the stale counter to zero: the check is never reached");
        assertEquals(0, infoPinState(), "so the card can never report itself blocked from here");
        assertEquals(CashuAppletTest.SW_OK,
            sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_SPEND_PROOF, 0, 0, new byte[32], 64)).getSW(),
            "a no-PIN card spends");

        // SET_PIN takes the card as it would a never-personalised one, and
        // OwnerPIN.update starts the new PIN at three tries: the stale count
        // never reaches the next holder.
        assertEquals(CashuAppletTest.SW_OK, send(CashuAppletTest.INS_SET_PIN, CashuAppletTest.NEW_PIN));
        assertEquals(1, infoPinState());
        assertEquals(0x63C2, verify(CashuAppletTest.WRONG_PIN), "three fresh tries, not one");
        assertEquals(0x63C1, verify(CashuAppletTest.WRONG_PIN));
        assertEquals(CashuAppletTest.SW_OK, verify(CashuAppletTest.NEW_PIN));
    }
}
