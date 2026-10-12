package nl.icthorse.horsesafe.ui

import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Written
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NavigationTest {

    private fun scr(s: State, p: Profile = Profile.BIO_MAIN, busy: Boolean = false, copy: Boolean = false, resume: Boolean = false, min: Boolean = true) =
        setupScreen(s, p, busy, copy, resume, min)

    @Test fun volgordeHoofdsleutel() {
        assertEquals(Screen.M2_CONNECT, scr(State.Idle))
        assertEquals(Screen.M2_CONNECT, scr(State.EnvOk(emptyList())))
        assertEquals(Screen.M3_JUDGEMENT, scr(State.GateNewOk))
        assertEquals(Screen.M4_REVEAL, scr(State.PinGenerated))
        assertEquals(Screen.M5_COPY, scr(State.PinGenerated, copy = true))
        assertEquals(Screen.M6_RETYPE, scr(State.PinShown))
        assertEquals(Screen.BUSY, scr(State.PinRetypedOk))
        assertEquals(Screen.BUSY, scr(State.PinSet(8)))
        assertEquals(Screen.M6B_IRREVERSIBLE, scr(State.CountsOk(0, 0)))
        assertEquals(Screen.BUSY, scr(State.CountsOk(0, 0), min = false))
        assertEquals(Screen.M7_FINGERS, scr(State.AlwaysUvOk))
        assertEquals(Screen.M7_FINGERS, scr(State.AlwaysUvOk, busy = true))
        assertEquals(Screen.BUSY, scr(State.FinalInspect))
        assertEquals(Screen.M10_REPORT, scr(State.Done))
        assertEquals(Screen.M11_STOP, scr(State.Stopped(Stop.KEY_REMOVED, setOf(Written.PIN), 0)))
    }

    @Test fun noodsleutelKrijgtGeenVingerscherm() {
        assertEquals(Screen.BUSY, scr(State.AlwaysUvOk, p = Profile.RECOVERY_YK5))
        assertEquals(Screen.BUSY, scr(State.AlwaysUvOk, p = Profile.RECOVERY_BIO))
    }

    @Test fun hervattenGaatViaM3NaarM8() {
        val s = State.GateResumeOk(setOf(Written.MIN_PIN_LENGTH_63))
        assertEquals(Screen.M3_JUDGEMENT, scr(s))
        assertEquals(Screen.M8_PIN_ENTRY, scr(s, resume = true))
        assertEquals(Screen.BUSY, scr(s, resume = true, busy = true))
    }

    @Test fun bezigWintBehalveBijStopEnRapport() {
        assertEquals(Screen.BUSY, scr(State.PinShown, busy = true))
        assertEquals(Screen.M11_STOP, scr(State.Stopped(Stop.CANCELLED, emptySet(), 0), busy = true))
    }

    @Test fun pinInGeheugenAlleenTussenGenererenEnEindinspectie() {
        assertFalse(machineHoldsPin(State.GateNewOk))
        assertTrue(machineHoldsPin(State.PinGenerated))
        assertTrue(machineHoldsPin(State.AlwaysUvOk))
        assertTrue(machineHoldsPin(State.FinalInspect))
        assertFalse(machineHoldsPin(State.Done))
        assertFalse(machineHoldsPin(State.Stopped(Stop.CANCELLED, emptySet(), 0)))
    }

    @Test fun stappenlijstPerProfiel() {
        val yk5 = stepsFor(Profile.RECOVERY_YK5, null).map { it.label }
        assertTrue(yk5.indexOf("Echtheid gekeurd (attestation)") < yk5.indexOf("PIN op de sleutel"))
        assertTrue("U2F gecontroleerd" in yk5)
        assertFalse(yk5.any { it.startsWith("Vingers") })
        val bio = stepsFor(Profile.BIO_MAIN, emptySet()).map { it.label }
        assertTrue(bio.indexOf("PIN op de sleutel") < bio.indexOf("Echtheid gekeurd (attestation)"))
        assertFalse("Minimum PIN-lengte 63 vastgezet" in bio)
    }

    @Test fun geheimeSchermenGemarkeerd() {
        assertEquals(setOf(Screen.M4_REVEAL, Screen.M5_COPY, Screen.M6_RETYPE, Screen.M8_PIN_ENTRY), Screen.entries.filter { it.holdsSecret }.toSet())
    }
}
