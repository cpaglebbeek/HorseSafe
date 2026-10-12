package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.flow.fake.FakeAttestationJudge
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.flow.fake.KeySpec
import nl.icthorse.horsesafe.flow.fake.SetupDriver
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.report.ReportCompare
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.yubikey.api.KeyError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** F4a/F4b keuren, F5 PIN wijzigen, F6 vingers beheren, F7 oefenen. */
class MaintenanceFlowsTest {

    private class Ready(val key: FakeYubiKey, val paper: CharArray, val report: nl.icthorse.horsesafe.report.Report)

    private suspend fun ready(spec: KeySpec = KeyProfiles.bioFido574(), profile: Profile = Profile.BIO_MAIN): Ready {
        val d = SetupDriver(FakeYubiKey(spec), profile)
        val end = d.runNew()
        assertTrue("inrichten: $end", end is State.ReportReady)
        d.key.log.clear()
        return Ready(d.key, d.paper!!, (end as State.ReportReady).report)
    }

    private fun keuring() = KeuringFlow(KeyProfiles.inspector(), FakeAttestationJudge, KeyProfiles.reports())

    private fun configCalls(key: FakeYubiKey) = key.log.filter { it == "setMinPinLength" || it == "toggleAlwaysUv" || it == "pinToken:ACFG" }

    // ---------------------------------------------------------------- F4a

    @Test fun keurenZonderPin() = runBlocking {
        val r = ready()
        val first = keuring().withoutPin(r.key, Profile.BIO_MAIN, null) as FlowOutcome.Done
        assertNull(first.stop)
        assertEquals(ReportKind.KEURING_ZONDER_PIN, first.report!!.kind)
        assertTrue("geen vorig rapport = oranje", first.report!!.checks.any { it.id == ReportCompare.CHECK_ID && it.verdict == Verdict.ORANGE })
        assertEquals(emptyList<String>(), r.key.writes())
        assertFalse(r.key.log.any { it.startsWith("pinToken") })

        val second = keuring().withoutPin(r.key, Profile.BIO_MAIN, r.report) as FlowOutcome.Done
        assertTrue(second.report!!.checks.any { it.id == ReportCompare.CHECK_ID && it.verdict == Verdict.GREEN })
        assertEquals(emptyList<String>(), second.report!!.differences)
    }

    @Test fun keurenZonderPinZietVerwisseldeSleutel() = runBlocking {
        val a = ready(KeyProfiles.bioFido574(serial = 31000001))
        val b = ready(KeyProfiles.bioFido574(serial = 31000999))
        val out = keuring().withoutPin(b.key, Profile.BIO_MAIN, a.report) as FlowOutcome.Done
        assertEquals(Stop.KEY_SWAPPED, out.stop)
        assertTrue("serialHmac" in out.report!!.differences)
    }

    @Test fun keurenZonderPinAlarmBijMinderPogingen() = runBlocking {
        val r = ready()
        try { r.key.ctap { pin.pinToken(SetupDriver.bufferOf(CharArray(63) { 'x' }), nl.icthorse.horsesafe.yubikey.api.Permission.CM) } ; fail() } catch (e: KeyError.PinInvalid) { }
        val out = keuring().withoutPin(r.key, Profile.BIO_MAIN, r.report) as FlowOutcome.Done
        assertEquals(Stop.PIN_READBACK_FAILED, out.stop)
        assertTrue(out.report!!.checks.any { it.id == "k_pin_retries" && it.verdict == Verdict.RED })
        assertTrue("pinRetries" in out.report!!.differences)
    }

    @Test fun keurenNoodsleutels() = runBlocking {
        val yk = ready(KeyProfiles.yk5_57(), Profile.RECOVERY_YK5)
        assertNull((keuring().withoutPin(yk.key, Profile.RECOVERY_YK5, yk.report) as FlowOutcome.Done).stop)
        val stays = ready(KeyProfiles.yk5U2fStays(), Profile.RECOVERY_YK5)
        val o = keuring().withoutPin(stays.key, Profile.RECOVERY_YK5, stays.report) as FlowOutcome.Done
        assertNull("U2F is oranje, geen stop", o.stop)
        val bio = ready(KeyProfiles.bioFido574(), Profile.RECOVERY_BIO)
        assertNull((keuring().withoutPin(bio.key, Profile.RECOVERY_BIO, bio.report) as FlowOutcome.Done).stop)
    }

    // ---------------------------------------------------------------- F4b

    @Test fun keurenMetPin() = runBlocking {
        val r = ready()
        val out = keuring().withPin(r.key, Profile.BIO_MAIN, SetupDriver.bufferOf(r.paper), r.report) as FlowOutcome.Done
        assertNull(out.stop)
        val rep = out.report!!
        assertEquals(ReportKind.KEURING_MET_PIN, rep.kind)
        assertEquals(0, rep.residentCredentials)
        assertEquals(2, rep.fingerCount)
        assertEquals(true, rep.attestationOk)
        assertEquals(emptyList<String>(), rep.differences)
        // Elk doel een eigen token; geen config.
        assertTrue(listOf("pinToken:CM", "pinToken:BE", "pinToken:MC").all { it in r.key.log })
        assertEquals(emptyList<String>(), configCalls(r.key))
        assertEquals(emptyList<String>(), r.key.writes())
    }

    @Test fun keurenMetPinFoutSyntaxEnBlokkade() = runBlocking {
        val r = ready()
        val wrong = r.paper.copyOf().also { it[5] = if (it[5] == 'k') 'm' else 'k' }
        assertEquals(FlowOutcome.PinRejected(7), keuring().withPin(r.key, Profile.BIO_MAIN, SetupDriver.bufferOf(wrong), r.report))
        r.key.log.clear()
        assertEquals(FlowOutcome.SyntaxInvalid, keuring().withPin(r.key, Profile.BIO_MAIN, SetupDriver.bufferOf(r.paper.copyOf(62)), r.report))
        assertFalse("geen poging bij syntaxfout", r.key.log.any { it.startsWith("pinToken") })
        assertEquals(7, r.key.pinRetries)
        // Naar 3 pogingen (met opnieuw insteken na 3 fouten op rij).
        repeat(2) { keuring().withPin(r.key, Profile.BIO_MAIN, SetupDriver.bufferOf(wrong), r.report) } // 6, dan 5 + power-cycle
        r.key.reinsert()
        repeat(2) { keuring().withPin(r.key, Profile.BIO_MAIN, SetupDriver.bufferOf(wrong), r.report) } // 4, 3
        assertEquals(3, r.key.pinRetries)
        r.key.log.clear()
        assertEquals(FlowOutcome.Blocked(Stop.PIN_RETRIES_LOW), keuring().withPin(r.key, Profile.BIO_MAIN, SetupDriver.bufferOf(r.paper), r.report))
        assertFalse(r.key.log.any { it.startsWith("pinToken") })
    }

    @Test fun keurenMetPinZietExtraVinger() = runBlocking {
        val r = ready()
        val ff = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports())
        assertTrue(ff.open(r.key, SetupDriver.bufferOf(r.paper)) is FlowOutcome.Ready)
        assertTrue(ff.add("L-duim") is FlowOutcome.Touch)
        ff.close()
        val out = keuring().withPin(r.key, Profile.BIO_MAIN, SetupDriver.bufferOf(r.paper), r.report) as FlowOutcome.Done
        assertTrue(out.report!!.differences.containsAll(listOf("fingerCount", "fingerNames", "fingerTemplateHashes")))
        assertTrue(out.report!!.checks.any { it.id == ReportCompare.CHECK_ID && it.verdict == Verdict.RED })
    }

    // ---------------------------------------------------------------- F5

    @Test fun pinWijzigen() = runBlocking {
        val r = ready()
        val f = ChangePinFlow(Profile.BIO_MAIN, KeyProfiles.inspector(), KeyProfiles.reports(),
            PinGenerator(nl.icthorse.horsesafe.flow.fake.CyclicSource(intArrayOf(21, 22, 23, 24, 25, 26, 27, 28, 9))))
        assertEquals(8, (f.begin(r.key) as FlowOutcome.Done).pinRetries)
        assertTrue(f.generateNewPin())
        val newPaper = f.revealNewPin { b -> b.useChars { it.copyOf() } }!!
        assertTrue(f.retypedGroupMatches(8, newPaper.copyOfRange(56, 63)))
        assertTrue(f.confirmRetyped(SetupDriver.bufferOf(newPaper)))
        // Syntax eerst: geen poging.
        assertEquals(FlowOutcome.SyntaxInvalid, f.submit(SetupDriver.bufferOf(r.paper.copyOf(10))))
        assertFalse("changePin" in r.key.log)
        // Foute huidige PIN kost een poging; flow blijft bruikbaar.
        val wrong = r.paper.copyOf().also { it[0] = if (it[0] == 'k') 'm' else 'k' }
        assertEquals(FlowOutcome.PinRejected(7), f.submit(SetupDriver.bufferOf(wrong)))
        val done = f.submit(SetupDriver.bufferOf(r.paper)) as FlowOutcome.Done
        assertNull(done.stop)
        assertEquals(ReportKind.PIN_CHANGE, done.report!!.kind)
        assertTrue(r.key.pinEquals(newPaper))
        assertEquals(8, r.key.pinRetries)
        assertEquals(63, r.key.minPinLength)
        assertEquals(emptyList<String>(), configCalls(r.key))
        assertNull("buffers gewist", f.revealNewPin { it })
    }

    @Test fun pinWijzigenGeblokkeerdBijDriePogingen() = runBlocking {
        val r = ready()
        r.key.preset(pin = r.paper, retries = 3, minLen = 63)
        val f = ChangePinFlow(Profile.BIO_MAIN, KeyProfiles.inspector(), KeyProfiles.reports())
        assertEquals(FlowOutcome.Blocked(Stop.PIN_RETRIES_LOW), f.begin(r.key))
        assertFalse(f.generateNewPin())
    }

    @Test fun pinWijzigenAlleenOpIngerichteSleutel() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574()).apply { preset(pin = CharArray(63) { 'k' }) } // minimum nog 4
        val f = ChangePinFlow(Profile.BIO_MAIN, KeyProfiles.inspector(), KeyProfiles.reports())
        assertEquals(FlowOutcome.Blocked(Stop.MIN_PIN_LENGTH_READBACK_FAILED), f.begin(key))
    }

    // ---------------------------------------------------------------- F6

    @Test fun vingersBeheren() = runBlocking {
        val r = ready()
        val ff = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports())
        val open = ff.open(r.key, SetupDriver.bufferOf(r.paper)) as FlowOutcome.Ready
        assertEquals(2, open.fingers.size)
        assertEquals(15, open.maxNameBytes)
        assertTrue(ff.add("L-duim") is FlowOutcome.Touch)
        assertTrue(ff.add("R-duim") is FlowOutcome.Touch)
        assertTrue(ff.add("R-midden") is FlowOutcome.Touch)
        assertEquals(5, r.key.fingerCount)
        assertTrue("max 5", ff.add("L-midden") is FlowOutcome.Refused)
        assertTrue(ff.rename(ff.current.first().templateId, "R-wijs2") is FlowOutcome.Touch) // F6.3: met testaanraking
        assertEquals("R-wijs2", r.key.fingerNames().first())
        assertTrue(ff.rename(ff.current.first().templateId, "a".repeat(16)) is FlowOutcome.Refused)
        assertTrue(ff.rename(ff.current.first().templateId, "Rück") is FlowOutcome.Refused)
        // Alles verwijderen; de laatste vraagt bevestiging.
        while (ff.current.size > 1) assertTrue(ff.remove(ff.current.first().templateId) is FlowOutcome.Touch)
        assertEquals(FlowOutcome.NeedsConfirmLast, ff.remove(ff.current.first().templateId))
        assertTrue(ff.remove(ff.current.first().templateId, confirmLast = true) is FlowOutcome.Ready)
        assertEquals(0, r.key.fingerCount)
        val rep = ff.close()
        assertNotNull(rep)
        assertEquals(ReportKind.FINGERS, rep!!.kind)
        assertEquals(emptyList<String>(), configCalls(r.key))
        // Na close geen acties meer.
        assertTrue(ff.add("X") is FlowOutcome.Blocked)
    }

    @Test fun vingersBeherenNietOpYk5EnTestaanrakingMislukt() = runBlocking {
        val yk = ready(KeyProfiles.yk5_57(), Profile.RECOVERY_YK5)
        assertEquals(FlowOutcome.Blocked(Stop.CLASS_MISMATCH), FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports()).open(yk.key, SetupDriver.bufferOf(yk.paper)))
        val r = ready()
        val ff = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports())
        ff.open(r.key, SetupDriver.bufferOf(r.paper))
        r.key.fingerMatches = false
        assertEquals(FlowOutcome.Touch(false, 2), ff.testTouch())
    }

    // ---------------------------------------------------------------- F7

    @Test fun oefenen() = runBlocking {
        val r = ready()
        val p = PracticeFlow()
        val buf = SetupDriver.bufferOf(r.paper)
        val checks = GroupCheck.checkChars(buf)
        assertEquals(emptyList<Int>(), p.checkPaper(buf, checks))
        val bad = checks.copyOf().also { it[3] = if (it[3] == 'k') 'm' else 'k' }
        assertEquals(listOf(4), p.checkPaper(buf, bad))
        assertTrue(p.checkGroup(r.paper, 0, checks[0]))
        // Echte controle: een foute poging, daarna de juiste zet de teller terug op 8.
        val wrong = r.paper.copyOf().also { it[0] = if (it[0] == 'k') 'm' else 'k' }
        assertEquals(FlowOutcome.PinRejected(7), p.verifyOnKey(r.key, SetupDriver.bufferOf(wrong)))
        assertEquals(FlowOutcome.Done(null, null, 8), p.verifyOnKey(r.key, SetupDriver.bufferOf(r.paper)))
        assertTrue("CM-permissie (kritiek 1)", "pinToken:CM" in r.key.log)
        assertEquals(emptyList<String>(), r.key.writes())
    }

    @Test fun pinTokenZonderPermissieFaaltOpDeFake() {
        val key = FakeYubiKey(KeyProfiles.bioFido574()).apply { preset(pin = CharArray(63) { 'k' }) }
        try { key.rawPinToken(CharArray(63) { 'k' }, null); fail() } catch (e: KeyError.Ctap) { assertEquals(0x14, e.code) }
        try { key.rawPinToken(CharArray(63) { 'k' }, 0); fail() } catch (e: KeyError.Ctap) { assertEquals(0x02, e.code) }
        key.rawPinToken(CharArray(63) { 'k' }, nl.icthorse.horsesafe.yubikey.api.Permission.CM.bit)
    }

    @Test fun fakeMinimumAlleenOmhoogEnForcePinChange() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.yk5_57()).apply { preset(pin = CharArray(10) { 'k' }) }
        key.ctap { pin.pinToken(SetupDriver.bufferOf(CharArray(10) { 'k' }), nl.icthorse.horsesafe.yubikey.api.Permission.ACFG).use { config.setMinPinLength63(it) } }
        assertTrue("PIN korter dan nieuw minimum → forcePinChange", key.forcePinChange)
        // Met forcePinChange geeft de sleutel geen token meer (CTAP 2.1).
        var leaked: nl.icthorse.horsesafe.yubikey.api.AuthToken? = null
        try {
            key.ctap { leaked = pin.pinToken(SetupDriver.bufferOf(CharArray(10) { 'k' }), nl.icthorse.horsesafe.yubikey.api.Permission.ACFG) }
        } catch (e: KeyError.PinPolicyViolation) { /* forcePinChange: geen token */ }
        assertNull(leaked)
    }
}
