package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.flow.fake.SetupDriver
import nl.icthorse.horsesafe.report.ReportJsonSchema
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.yubikey.api.ConfigOps
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Happy paths F2 (hoofdsleutel), F3 (noodsleutel YK5 en Bio zonder vinger) en de vaste volgorde. */
class SetupFlowTest {

    private fun idx(log: List<String>, op: String): Int = log.indexOf(op).also { assertTrue("$op ontbreekt in $log", it >= 0) }

    private fun assertStrictlyIncreasing(h: List<State>) {
        for (i in 1 until h.size) assertTrue("terugwaarts: ${h[i - 1]} -> ${h[i]}", h[i].order > h[i - 1].order)
    }

    @Test fun hoofdsleutelBioHappyPath() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        val end = d.runNew("R-wijs", "L-wijs")
        assertTrue("eind: $end", end is State.ReportReady)
        val h = d.machine.history
        assertStrictlyIncreasing(h)
        val kinds = h.map { it::class.simpleName }
        assertEquals(
            listOf("Idle", "EnvOk", "Detected", "GateNewOk", "PinGenerated", "PinShown", "PinRetypedOk", "PinSet",
                "AttestOkAfterPin", "CountsOk", "ConfirmIrreversible", "MinLenSet", "AlwaysUvOk", "FingersOk", "FinalInspect", "ReportReady"),
            kinds,
        )
        val log = d.key.log
        // Bio met alwaysUv=true: setPin < attest(token) < setMinPinLength; alwaysUv NIET getoggeld.
        assertTrue(idx(log, "setPin") < idx(log, "makeCredential:token"))
        assertTrue(idx(log, "makeCredential:token") < idx(log, "setMinPinLength"))
        assertFalse("alwaysUv mag niet getoggeld worden", "toggleAlwaysUv" in log)
        assertTrue(idx(log, "setMinPinLength") < idx(log, "enroll"))
        // Tellen met eigen tokens (CM, BE), config met ACFG.
        assertTrue("pinToken:CM" in log && "pinToken:BE" in log && "pinToken:ACFG" in log && "pinToken:MC" in log)
        // Sleutel.
        val k = d.key
        assertEquals(63, k.minPinLength)
        assertEquals(listOf(ConfigOps.MIN_PIN_RP_ID), k.minPinRpIds)
        assertFalse(k.forcePinChange)
        assertEquals(true, k.alwaysUv)
        assertEquals(2, k.fingerCount)
        assertEquals(8, k.pinRetries)
        assertTrue(k.pinEquals(d.paper!!))
        // Rapport.
        val r = (end as State.ReportReady).report
        assertEquals(ReportKind.SETUP, r.kind)
        assertEquals(2, r.fingerCount)
        assertEquals(listOf("R-wijs", "L-wijs"), r.fingerNames)
        assertEquals(0, r.residentCredentials)
        assertEquals(true, r.attestationOk)
        assertEquals(63, r.minPinLength)
        assertNotNull(r.serialHmac)
        assertNull(r.stop)
        ReportJsonSchema.fromJson(ReportJsonSchema.toJson(r)) // whitelist-rondgang
        // Afsluiten.
        assertEquals(State.Done, d.send(FlowEvent.Quit))
        assertNull(d.machine.revealPin { it })
    }

    @Test fun bioMetAlwaysUvUitAttesteertVoorDePinEnTogglet() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioAlwaysUvOff()), Profile.BIO_MAIN)
        val end = d.runNew()
        assertTrue("eind: $end", end is State.ReportReady)
        val log = d.key.log
        assertTrue(idx(log, "makeCredential:up") < idx(log, "setPin"))
        assertFalse("makeCredential:token" in log)
        assertEquals(1, log.count { it == "toggleAlwaysUv" })
        assertTrue(idx(log, "setMinPinLength") < idx(log, "toggleAlwaysUv"))
        assertTrue(d.machine.history.any { it is State.AttestOkBeforePin })
        assertEquals(true, d.key.alwaysUv)
    }

    @Test fun noodsleutelYk5() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.yk5_57()), Profile.RECOVERY_YK5)
        val end = d.runNew()
        assertTrue("eind: $end", end is State.ReportReady)
        val log = d.key.log
        // YK5: attest vóór setPin, met alleen een aanraking.
        assertTrue(idx(log, "makeCredential:up") < idx(log, "setPin"))
        assertTrue(idx(log, "setPin") < idx(log, "setMinPinLength"))
        assertTrue(idx(log, "setMinPinLength") < idx(log, "toggleAlwaysUv"))
        assertFalse(log.any { it.startsWith("enroll") || it == "pinToken:BE" })
        assertTrue(d.machine.history.contains(State.U2fChecked(false)))
        assertFalse("U2F_V2" in d.key.versions)
        val r = (end as State.ReportReady).report
        assertNull(r.fingerCount)
        assertEquals("yubikey5", r.keyClass)
        assertTrue(r.checks.any { it.id == "u2f_after_always_uv" && it.verdict == Verdict.GREEN })
    }

    @Test fun yk5DieU2fHoudtIsOranjeGeenStop() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.yk5U2fStays()), Profile.RECOVERY_YK5)
        val end = d.runNew()
        assertTrue("eind: $end", end is State.ReportReady)
        assertTrue(d.machine.history.contains(State.U2fChecked(true)))
        val r = (end as State.ReportReady).report
        assertTrue(r.checks.any { it.id == "u2f_after_always_uv" && it.verdict == Verdict.ORANGE })
    }

    @Test fun noodsleutelBioZonderVinger() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.RECOVERY_BIO)
        val end = d.runNew()
        assertTrue("eind: $end", end is State.ReportReady)
        assertFalse(d.key.log.any { it.startsWith("enroll") })
        assertFalse("toggleAlwaysUv" in d.key.log)
        val r = (end as State.ReportReady).report
        assertEquals(0, r.fingerCount)
        assertEquals(0, d.key.fingerCount)
    }

    @Test fun hertypenMetFoutBlijftStaanEnKostNiets() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d.detect()
        d.send(FlowEvent.ChecklistConfirmed)
        val paper = d.machine.revealPin { b -> b.useChars { it.copyOf() } }!!
        d.send(FlowEvent.RevealFinished)
        // M5 per groep.
        assertTrue(d.machine.retypedGroupMatches(0, paper.copyOfRange(0, 7)))
        val wrong = paper.copyOf().also { it[10] = if (it[10] == 'k') 'm' else 'k' }
        assertFalse(d.machine.retypedGroupMatches(1, wrong.copyOfRange(7, 14)))
        val s = d.send(FlowEvent.PinRetyped(SetupDriver.bufferOf(wrong)))
        assertEquals(State.PinShown, s)
        assertNotNull(d.machine.notice.value)
        assertFalse("setPin" in d.key.log)
        val ok = d.send(FlowEvent.PinRetyped(SetupDriver.bufferOf(paper)))
        assertTrue("na juist hertypen: $ok", ok is State.CountsOk)
    }

    @Test fun minimumAlleenNaBevestiging() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d.detect()
        val s = d.pinUntilRetyped()
        assertTrue(s is State.CountsOk)
        assertFalse("setMinPinLength" in d.key.log)
        // Vingers of klaar vóór de bevestiging doen niets.
        d.send(FlowEvent.EnrollFinger("R-wijs"))
        d.send(FlowEvent.FingersDone)
        assertTrue(d.state is State.CountsOk)
        assertFalse(d.key.log.any { it.startsWith("enroll") })
        assertTrue(d.confirmIrreversible() is State.AlwaysUvOk)
    }

    @Test fun vingerregels() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d.detect(); d.pinUntilRetyped(); d.confirmIrreversible()
        // Eén vinger is te weinig.
        d.send(FlowEvent.EnrollFinger("R-wijs"))
        assertTrue(d.send(FlowEvent.FingersDone) is State.AlwaysUvOk)
        // Naam te lang (> 15 bytes) en niet-ASCII worden geweigerd zonder sleutelverkeer.
        val before = d.key.log.count { it == "enroll" }
        d.send(FlowEvent.EnrollFinger("R-wijsvinger-lang"))
        d.send(FlowEvent.EnrollFinger("R-duimé"))
        d.send(FlowEvent.EnrollFinger("R-wijs")) // dubbel
        assertEquals(before, d.key.log.count { it == "enroll" })
        // CaptureError wordt gemeld en de inschrijving gaat door.
        d.key.captureErrors += nl.icthorse.horsesafe.yubikey.api.SampleFeedback.TOO_FAST
        d.send(FlowEvent.EnrollFinger("L-wijs"))
        d.send(FlowEvent.EnrollFinger("L-duim"))
        d.send(FlowEvent.EnrollFinger("R-duim")) // vierde: geweigerd bij inrichten
        assertEquals(3, d.key.fingerCount)
        val end = d.send(FlowEvent.FingersDone)
        assertTrue("eind: $end", end is State.ReportReady)
        assertEquals(3, (end as State.ReportReady).report.fingerCount)
    }

    @Test fun timeoutBijAanrakingIsHerstelbaarMetRetry() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.yk5_57())
        val d = SetupDriver(key, Profile.RECOVERY_YK5)
        d.detect()
        key.touchResponds = false
        val s = d.pinUntilRetyped()
        assertEquals(State.PinRetypedOk, s)
        assertNotNull(d.machine.notice.value)
        assertFalse("setPin" in key.log)
        key.touchResponds = true
        val s2 = d.send(FlowEvent.Retry)
        assertTrue("na retry: $s2", s2 is State.CountsOk)
    }

    @Test fun maxPinLengthOnbekendMetBeleidAllowIfFido() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioNo1D()), Profile.BIO_MAIN, policy = MaxPinLengthPolicy.ALLOW_IF_FIDO)
        val end = d.runNew()
        assertTrue("eind: $end", end is State.ReportReady)
        val r = (end as State.ReportReady).report
        assertTrue(r.checks.any { it.id == "max_pin_length" && it.verdict == Verdict.ORANGE })
        assertNull(r.maxPinLength)
    }
}
