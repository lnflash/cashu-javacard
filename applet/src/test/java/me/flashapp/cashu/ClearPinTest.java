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
 * D15: CLEAR_PIN's one persistent write is the pinState byte, after the check.
 *
 * CLEAR_PIN has nothing to order. Its successful pin.check already reset the
 * OwnerPIN's try counter to its limit (OwnerPIN.check's contract: a match
 * sets the validated flag and resets the tries remaining), so the only
 * persistent write left is pinState to 0, a single byte the JCRE writes
 * atomically. A card pulled mid-command is PIN-set or it is not; there is no
 * state between. An earlier draft followed the byte with
 * pin.resetAndUnblock() inside a JCSystem transaction and described the
 * order of the two as load-bearing — it was not, since the counter was
 * already full before either ran — so the scan here now says the opposite:
 * the check precedes the write, and the state byte is the only persistent
 * write there is.
 *
 * jCardSim cannot tear a write, so this is checked as D14's order is: the
 * shape is scanned in the source, and the state the old comment worried
 * about — pinState 0 over a partly spent counter — is set on the card
 * directly and shown to be harmless. CLEAR_PIN cannot leave that state; the
 * test keeps it as a defensive property of pinState 0, which no command reads
 * the counter behind.
 */
class ClearPinTest {

    // ── the shape, in the source ─────────────────────────────────────────────

    @Test
    @DisplayName("CLEAR_PIN's only persistent write is pinState 0, after the PIN check")
    void appletWritesTheStateByteAloneAfterTheCheck() throws Exception {
        String src = new String(
            java.nio.file.Files.readAllBytes(
                SchnorrHWMathTest.mainSourceDir().resolve("CashuApplet.java")),
            java.nio.charset.StandardCharsets.UTF_8);
        List<String> violations = clearPinViolations(src);
        assertTrue(violations.isEmpty(), String.join("\n", violations));
    }

    @Test
    @DisplayName("the scan fails a write before the check, a clear that never writes the state, and a second persistent write")
    void theScanCanSayNo() {
        String beforeCheck = "class A { private void processClearPin(APDU apdu) {"
            + " pinState[0] = (byte) 0;"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " } }";
        String noState = "class A { private void processClearPin(APDU apdu) {"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " pinVerifiedFlag[0] = (byte) 0;"
            + " } }";
        String noCheck = "class A { private void processClearPin(APDU apdu) {"
            + " pinState[0] = (byte) 0;"
            + " } }";
        String counterReset = "class A { private void processClearPin(APDU apdu) {"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " pinState[0] = (byte) 0;"
            + " pin.resetAndUnblock();"
            + " } }";
        String transaction = "class A { private void processClearPin(APDU apdu) {"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " JCSystem.beginTransaction();"
            + " pinState[0] = (byte) 0;"
            + " JCSystem.commitTransaction();"
            + " } }";
        String pinRewrite = "class A { private void processClearPin(APDU apdu) {"
            + " if (!pin.check(buf, off, pinLen)) failPinCheck();"
            + " pinState[0] = (byte) 0;"
            + " pin.update(buf, off, pinLen);"
            + " } }";
        String good = "class A { private void processClearPin(APDU apdu) {"
            + " requireNotLocked(); requirePinVerified();"
            + " boolean ok = pin.check(buf, off, pinLen);"
            + " if (!ok) failPinCheck();"
            + " pinState[0] = (byte) 0;"
            + " pinVerifiedFlag[0] = (byte) 0;"
            + " } }";

        assertFalse(clearPinViolations(beforeCheck).isEmpty(), "write before the PIN check passed");
        assertFalse(clearPinViolations(noState).isEmpty(), "clear that never writes pinState passed");
        assertFalse(clearPinViolations(noCheck).isEmpty(), "clear without a PIN check passed");
        assertFalse(clearPinViolations(counterReset).isEmpty(), "a counter reset after the check passed");
        assertFalse(clearPinViolations(transaction).isEmpty(), "a transaction around the one byte passed");
        assertFalse(clearPinViolations(pinRewrite).isEmpty(), "a PIN rewrite in the clear passed");
        assertTrue(clearPinViolations(good).isEmpty(), String.join("\n", clearPinViolations(good)));
    }

    /**
     * Violations of the CLEAR_PIN write rule in processClearPin:
     * - the PIN check (pin.check) does not precede the pinState write;
     * - pinState is never set to 0;
     * - the OwnerPIN is written after the check (pin.resetAndUnblock, which
     *   resets a counter the check already reset, or pin.update, which is
     *   SET_PIN's job), or the byte is wrapped in a JCSystem transaction, so
     *   that the state byte is no longer the one persistent write and the
     *   javadoc, D15 and APDU.md stop telling the truth about it.
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
        int state = body.indexOf("pinState[0] = (byte) 0");

        if (check < 0) violations.add("processClearPin never checks the PIN");
        if (state < 0) violations.add("processClearPin never sets pinState to 0");
        if (body.contains("pin.resetAndUnblock()")) {
            violations.add("processClearPin resets the try counter: the successful pin.check already left it"
                + " at its limit, and the state byte is meant to be the only persistent write");
        }
        if (body.contains("pin.update(")) {
            violations.add("processClearPin rewrites the PIN: that is SET_PIN's job, and the state byte is"
                + " meant to be the only persistent write");
        }
        if (body.contains("JCSystem.beginTransaction()") || body.contains("JCSystem.commitTransaction()")) {
            violations.add("processClearPin opens a transaction around a single atomic byte write: nothing"
                + " for it to make atomic, and a reader of it would look for a second write to protect");
        }
        if (check >= 0 && state >= 0 && check > state) {
            violations.add("processClearPin writes before the PIN check: a wrong PIN must change nothing");
        }
        return violations;
    }

    // ── pinState 0 over a partly spent counter ───────────────────────────────

    /** A runtime that hands the test its applet, so pinState can be set directly. */
    private static final class ExposedRuntime extends SimulatorRuntime {
        Applet appletAt(AID aid) {
            return getApplet(aid);
        }
    }

    private static final byte CLA = CashuAppletTest.CLA;
    private CardSimulator sim;
    private byte[] pinState;
    private OwnerPIN pin;

    private void freshCard() throws Exception {
        ExposedRuntime runtime = new ExposedRuntime();
        sim = new CardSimulator(runtime);
        AID aid = AIDUtil.create(CashuAppletTest.AID_HEX);
        sim.installApplet(aid, CashuApplet.class);
        assertEquals(CashuAppletTest.SW_OK, sim.transmitCommand(new CommandAPDU(
            0x00, 0xA4, 0x04, 0x00, CashuAppletTest.hexToBytes(CashuAppletTest.AID_STR))).getSW());
        Applet applet = runtime.appletAt(aid);
        java.lang.reflect.Field field = CashuApplet.class.getDeclaredField("pinState");
        field.setAccessible(true);
        pinState = (byte[]) field.get(applet);
        java.lang.reflect.Field pinField = CashuApplet.class.getDeclaredField("pin");
        pinField.setAccessible(true);
        pin = (OwnerPIN) pinField.get(applet);
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
    @DisplayName("a no-PIN card over a partly spent counter never reads it: VERIFY_PIN is 6984, spending is open, and SET_PIN starts the counter fresh (defensive: CLEAR_PIN cannot leave this state, its check fills the counter first)")
    void aNoPinCardNeverReadsThePartlySpentCounterBehindIt() throws Exception {
        freshCard();
        assertEquals(CashuAppletTest.SW_OK,
            send(CashuAppletTest.INS_LOAD_PROOF, CashuAppletTest.PROOF_1));
        assertEquals(CashuAppletTest.SW_OK, send(CashuAppletTest.INS_SET_PIN, CashuAppletTest.TEST_PIN));

        // Run the counter down to one try. A successful VERIFY_PIN resets it,
        // so the two wrong tries come after the right one; the session is
        // then over (failPinCheck). No CLEAR_PIN can run from here — it needs
        // the verified session the wrong tries just ended, and the check that
        // opens one refills the counter — which is the point: the state below
        // is one the applet must tolerate, not one it can produce.
        assertEquals(CashuAppletTest.SW_OK, verify(CashuAppletTest.TEST_PIN));
        assertEquals(0x63C2, verify(CashuAppletTest.WRONG_PIN));
        assertEquals(0x63C1, verify(CashuAppletTest.WRONG_PIN));

        // pinState 0 over an OwnerPIN still at one try remaining.
        assertEquals(1, pin.getTriesRemaining());
        pinState[0] = 0;

        assertEquals(0, infoPinState(), "GET_INFO reports no PIN");
        assertEquals(CashuAppletTest.SW_PIN_NOT_SET, verify(CashuAppletTest.TEST_PIN),
            "VERIFY_PIN has nothing to verify, whatever the counter says");
        assertEquals(CashuAppletTest.SW_PIN_NOT_SET, verify(CashuAppletTest.WRONG_PIN),
            "and a wrong PIN cannot run the counter to zero: the check is never reached");
        assertEquals(0, infoPinState(), "so the card can never report itself blocked from here");
        assertEquals(CashuAppletTest.SW_OK,
            sim.transmitCommand(new CommandAPDU(CLA, CashuAppletTest.INS_SPEND_PROOF, 0, 0, new byte[32], 64)).getSW(),
            "a no-PIN card spends");

        // SET_PIN takes the card as it would a never-personalised one, and
        // OwnerPIN.update starts the new PIN at three tries: the old count
        // never reaches the next holder.
        assertEquals(CashuAppletTest.SW_OK, send(CashuAppletTest.INS_SET_PIN, CashuAppletTest.NEW_PIN));
        assertEquals(1, infoPinState());
        assertEquals(0x63C2, verify(CashuAppletTest.WRONG_PIN), "three fresh tries, not one");
        assertEquals(0x63C1, verify(CashuAppletTest.WRONG_PIN));
        assertEquals(CashuAppletTest.SW_OK, verify(CashuAppletTest.NEW_PIN));
    }

    // ── the counter after a real CLEAR_PIN ───────────────────────────────────

    @Test
    @DisplayName("a successful OwnerPIN.check refills the counter on its own, so CLEAR_PIN leaves it full without writing it")
    void theCheckBeforeTheClearLeavesTheCounterFull() throws Exception {
        freshCard();
        assertEquals(CashuAppletTest.SW_OK, send(CashuAppletTest.INS_SET_PIN, CashuAppletTest.TEST_PIN));

        // The contract the applet leans on, shown on the OwnerPIN the applet
        // holds: two wrong tries bring the counter to one, and the next
        // successful check alone takes it back to the limit. CLEAR_PIN's
        // own check does the same, which is why it writes nothing to the
        // counter.
        assertEquals(0x63C2, verify(CashuAppletTest.WRONG_PIN));
        assertEquals(0x63C1, verify(CashuAppletTest.WRONG_PIN));
        assertEquals(1, pin.getTriesRemaining());
        assertEquals(CashuAppletTest.SW_OK, verify(CashuAppletTest.TEST_PIN));
        assertEquals(CashuApplet.PIN_MAX_TRIES, pin.getTriesRemaining(),
            "a successful check resets the counter; nothing in the applet wrote it");

        assertEquals(CashuAppletTest.SW_OK,
            send(CashuAppletTest.INS_CLEAR_PIN, CashuAppletTest.clearPinData(CashuAppletTest.TEST_PIN)));
        assertEquals(0, infoPinState(), "the PIN is gone");
        assertEquals(CashuApplet.PIN_MAX_TRIES, pin.getTriesRemaining(),
            "and the counter behind pinState 0 is full, as SET_PIN found it");

        assertEquals(CashuAppletTest.SW_OK, send(CashuAppletTest.INS_SET_PIN, CashuAppletTest.NEW_PIN));
        assertEquals(0x63C2, verify(CashuAppletTest.WRONG_PIN), "three fresh tries");
        assertEquals(0x63C1, verify(CashuAppletTest.WRONG_PIN));
        assertEquals(CashuAppletTest.SW_OK, verify(CashuAppletTest.NEW_PIN));
    }
}
