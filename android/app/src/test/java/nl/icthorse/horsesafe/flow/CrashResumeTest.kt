package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.flow.fake.KeySpec
import nl.icthorse.horsesafe.flow.fake.SetupDriver
import nl.icthorse.horsesafe.report.ReportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Crash-na-elke-stap-matrix (kritiek 2): de sleutel wordt na elke CTAP-aanroep van de inrichting
 * "uitgetrokken". Daarna moet óf een nieuwe inrichting kunnen (er staat nog niets), óf "Inrichting
 * hervatten" de sleutel afmaken, óf (alles staat er al) keuren met PIN groen zijn.
 */
class CrashResumeTest {

    private data class Point(val op: String, val nth: Int = 1)

    private suspend fun crashAndRecover(spec: KeySpec, profile: Profile, p: Point): String {
        val key = FakeYubiKey(spec)
        key.crashAfter = p.op
        key.crashAfterNth = p.nth
        val first = SetupDriver(key, profile)
        val s = first.runNew()
        assertTrue("$p: verwacht stop, kreeg $s", s is State.Stopped)
        val stop = s as State.Stopped
        assertEquals("$p", Stop.KEY_REMOVED, stop.stop)
        val paper = first.paper
        key.reinsert()

        if (key.pin == null) {
            // Er staat nog niets: hervatten mag niet, opnieuw beginnen wel.
            assertEquals(Stop.RESUME_NOT_ALLOWED, (SetupDriver(key, profile, SetupMode.RESUME).runResume(CharArray(63) { 'a' }) as State.Stopped).stop)
            assertTrue("$p: nieuw", SetupDriver(key, profile).runNew() is State.ReportReady)
            return "nieuw"
        }
        assertTrue("$p: Written.PIN gemeld", Written.PIN in stop.written)
        assertNotNull(paper)
        val r = SetupDriver(key, profile, SetupMode.RESUME)
        val end = r.runResume(paper!!)
        if (end is State.Stopped && end.stop == Stop.RESUME_NOT_ALLOWED) {
            // Alles staat al op de sleutel: keuren met PIN moet groen zijn.
            val flow = KeuringFlow(KeyProfiles.inspector(), nl.icthorse.horsesafe.flow.fake.FakeAttestationJudge, KeyProfiles.reports())
            val k = flow.withPin(key, profile, SetupDriver.bufferOf(paper), null) as FlowOutcome.Done
            assertNull("$p: keuring ${k.report?.checks}", k.stop)
            return "compleet"
        }
        assertTrue("$p: hervatten eindigde in $end", end is State.ReportReady)
        assertEquals(ReportKind.RESUME, (end as State.ReportReady).report.kind)
        assertKeyComplete(key, profile)
        // Monotoon, ook bij hervatten.
        val h = r.machine.history
        for (i in 1 until h.size) assertTrue(h[i].order > h[i - 1].order)
        return "hervat"
    }

    private fun assertKeyComplete(key: FakeYubiKey, profile: Profile) {
        assertEquals(63, key.minPinLength)
        assertEquals(false, key.forcePinChange)
        assertEquals(true, key.alwaysUv)
        assertEquals(8, key.pinRetries)
        when (profile) {
            Profile.BIO_MAIN -> assertTrue(key.fingerCount in 2..3)
            else -> assertEquals(0, key.fingerCount)
        }
    }

    @Test fun matrixHoofdsleutel() = runBlocking {
        val points = listOf(
            Point("readManagement"), Point("freshInfo"), Point("setPin"), Point("makeCredential:token"),
            Point("metadata"), Point("enumerate"), Point("setMinPinLength"), Point("readRawInfo", 2),
            Point("enroll", 1), Point("uvToken", 1), Point("enroll", 2), Point("uvToken", 2),
        )
        val outcomes = points.associateWith { crashAndRecover(KeyProfiles.bioFido574(), Profile.BIO_MAIN, it) }
        assertEquals("nieuw", outcomes[Point("readManagement")])
        assertEquals("hervat", outcomes[Point("setPin")])
        assertEquals("hervat", outcomes[Point("setMinPinLength")])
        assertEquals("hervat", outcomes[Point("enroll", 1)])
        assertEquals("compleet", outcomes[Point("enroll", 2)])
    }

    @Test fun matrixHoofdsleutelAlwaysUvUit() = runBlocking {
        listOf(Point("makeCredential:up"), Point("setPin"), Point("setMinPinLength"), Point("toggleAlwaysUv"), Point("enroll", 1))
            .forEach { crashAndRecover(KeyProfiles.bioAlwaysUvOff(), Profile.BIO_MAIN, it) }
    }

    @Test fun matrixNoodsleutelYk5() = runBlocking {
        val outcomes = listOf(
            Point("makeCredential:up"), Point("setPin"), Point("metadata"), Point("setMinPinLength"),
            Point("toggleAlwaysUv"), Point("freshInfo", 6),
        ).associateWith { crashAndRecover(KeyProfiles.yk5_57(), Profile.RECOVERY_YK5, it) }
        assertEquals("nieuw", outcomes[Point("makeCredential:up")])
        assertEquals("hervat", outcomes[Point("setPin")])
        assertEquals("hervat", outcomes[Point("setMinPinLength")])
        assertEquals("compleet", outcomes[Point("toggleAlwaysUv")])
    }

    @Test fun matrixNoodsleutelBio() = runBlocking {
        listOf(Point("setPin"), Point("makeCredential:token"), Point("setMinPinLength"))
            .forEach { crashAndRecover(KeyProfiles.bioFido574(), Profile.RECOVERY_BIO, it) }
    }

    @Test fun hervattenMetFoutePinKostEenPogingEnBlokkeertBijDrie() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574())
        key.crashAfter = "setPin"
        val first = SetupDriver(key, Profile.BIO_MAIN)
        first.runNew()
        key.reinsert()
        val paper = first.paper!!
        val wrong = paper.copyOf().also { it[0] = if (it[0] == 'k') 'm' else 'k' }

        val r = SetupDriver(key, Profile.BIO_MAIN, SetupMode.RESUME)
        r.detect()
        assertTrue(r.state is State.GateResumeOk)
        assertEquals(setOf(Written.MIN_PIN_LENGTH_63, Written.FINGERPRINTS), (r.state as State.GateResumeOk).pending)
        r.send(FlowEvent.PinEntered(SetupDriver.bufferOf(wrong)))
        assertTrue(r.state is State.GateResumeOk)
        assertEquals(7, r.machine.notice.value?.pinRetriesLeft)
        // Syntaxfout kost geen poging.
        r.send(FlowEvent.PinEntered(SetupDriver.bufferOf(paper.copyOf(62))))
        assertEquals(7, key.pinRetries)
        // Juist: door, teller terug op 8.
        r.send(FlowEvent.PinEntered(SetupDriver.bufferOf(paper)))
        assertTrue("na juiste PIN: ${r.state}", r.state is State.CountsOk)
        assertEquals(8, key.pinRetries)

        // Weinig pogingen: hervat-gate stopt vóór de invoer.
        val k2 = FakeYubiKey(KeyProfiles.bioFido574()).apply { preset(pin = paper, retries = 3) }
        assertEquals(Stop.PIN_RETRIES_LOW, (SetupDriver(k2, Profile.BIO_MAIN, SetupMode.RESUME).also { it.detect() }.state as State.Stopped).stop)
    }

    @Test fun hervattenWeigertResidentCredentials() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574())
        val paper = CharArray(63) { 'k' }
        key.preset(pin = paper, resident = 1)
        val end = SetupDriver(key, Profile.BIO_MAIN, SetupMode.RESUME).runResume(paper)
        assertEquals(Stop.KEY_ALREADY_USED, (end as State.Stopped).stop)
        assertEquals(4, key.minPinLength)
    }
}
