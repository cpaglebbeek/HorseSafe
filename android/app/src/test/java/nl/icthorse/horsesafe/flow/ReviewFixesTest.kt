package nl.icthorse.horsesafe.flow

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.time.Instant
import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.flow.fake.SetupDriver
import nl.icthorse.horsesafe.report.RawSerialKey
import nl.icthorse.horsesafe.report.ReportFixtures
import nl.icthorse.horsesafe.report.ReportSchemaException
import nl.icthorse.horsesafe.report.ReportStore
import nl.icthorse.horsesafe.report.SerialHasher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Tests bij de review-bevindingen van Miller deel 1 (flow- en rapportkant). */
class ReviewFixesTest {

    // ---------------------------------------------------------------- setPin: antwoord verloren, daarna Retry

    @Test fun setPinTimeOutNaUitvoerenDanRetryMeldtPinWelGezet() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574())
        key.timeoutAfterSetPin = true
        val d = SetupDriver(key, Profile.BIO_MAIN)
        d.detect()
        val afterRetype = d.pinUntilRetyped()
        assertFalse("time-out is herstelbaar, geen stop: $afterRetype", afterRetype is State.Stopped)
        assertTrue("PIN staat al op de sleutel", key.pinEquals(d.paper!!))
        val s = d.send(FlowEvent.Retry) as State.Stopped
        assertEquals(Stop.PIN_STATE_UNKNOWN, s.stop)
        assertTrue("M11 meldt dat de PIN er staat", Written.PIN in s.written)
        assertTrue("PIN niet overschreven", key.pinEquals(d.paper!!))
        assertEquals(8, key.pinRetries)
        d.paper!!.fill('\u0000')
    }

    @Test fun setPinZonderHerhalingGeeftNogSteedsPinAlreadySet() = runBlocking {
        // Kale gate-route: sleutel met PIN stopt vóór setPin (geen regressie).
        val key = FakeYubiKey(KeyProfiles.bioFido574()).apply { preset(pin = CharArray(63) { 'k' }) }
        val d = SetupDriver(key, Profile.BIO_MAIN)
        val s = d.detect() as State.Stopped
        assertEquals(Stop.PIN_ALREADY_SET, s.stop)
        assertTrue(s.written.isEmpty())
    }

    // ---------------------------------------------------------------- UV_BLOCKED bij de testaanraking

    @Test fun uvBlockedBijTestaanrakingWordtMetPinHersteld() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574())
        val d = SetupDriver(key, Profile.BIO_MAIN)
        d.detect(); d.pinUntilRetyped(); d.confirmIrreversible()
        assertEquals(State.AlwaysUvOk, d.state)
        key.uvBlockOnNextTouch = true // testaanraking na de inschrijving geeft UV_BLOCKED
        val s1 = d.send(FlowEvent.EnrollFinger("R-wijs"))
        assertEquals("geen harde stop bij UV_BLOCKED", State.AlwaysUvOk, s1)
        assertEquals("uvRetries teruggezet via PIN-token", 3, key.uvRetries)
        assertTrue(d.machine.notice.value!!.text.contains("hersteld"))
        d.send(FlowEvent.EnrollFinger("L-wijs"))
        val end = d.send(FlowEvent.FingersDone)
        assertTrue("inrichting loopt door: $end", end is State.ReportReady)
        d.paper!!.fill('\u0000')
    }

    @Test fun uvBlockedHeeftEigenStop() {
        assertEquals(Stop.UV_BLOCKED, ErrorMap.stopFor(nl.icthorse.horsesafe.yubikey.api.KeyError.UvBlocked()))
    }

    @Test fun vingersBeherenHerstelt_UvBlocked_EnHernoemenDoetTestaanraking() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        assertTrue(d.runNew() is State.ReportReady)
        val ff = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports())
        assertTrue(ff.open(d.key, SetupDriver.bufferOf(d.paper!!)) is FlowOutcome.Ready)
        d.key.uvBlockOnNextTouch = true
        val t = ff.testTouch()
        assertTrue("UV_BLOCKED = herstelbaar: $t", t is FlowOutcome.Retriable)
        assertEquals(3, d.key.uvRetries)
        assertEquals(FlowOutcome.Touch(true, 3), ff.testTouch())
        d.key.log.clear()
        val r = ff.rename(ff.current.first().templateId, "R-wijs2")
        assertTrue("hernoemen eindigt met testaanraking: $r", r is FlowOutcome.Touch)
        assertTrue(d.key.log.any { it.startsWith("uvToken") })
        ff.close()
        d.paper!!.fill('\u0000')
    }

    // ---------------------------------------------------------------- F6 alleen hoofdsleutel

    @Test fun vingersBeherenWeigertNoodsleutelBio() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.RECOVERY_BIO)
        val end = d.runNew()
        assertTrue("noodsleutel-Bio ingericht: $end", end is State.ReportReady)
        val serial = (end as State.ReportReady).report.serialHmac!!
        d.key.log.clear()

        // Rapport zegt: noodsleutel.
        val known = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports(), knownProfileOf = { if (it == serial) Profile.RECOVERY_BIO else null })
        assertEquals(FlowOutcome.Blocked(Stop.RECOVERY_KEY_NO_FINGERS), known.open(d.key, SetupDriver.bufferOf(d.paper!!)))
        // Geen rapport en geen vinger: ook weigeren (niet vast te stellen dat het de hoofdsleutel is).
        val unknown = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports())
        assertEquals(FlowOutcome.Blocked(Stop.RECOVERY_KEY_NO_FINGERS), unknown.open(d.key, SetupDriver.bufferOf(d.paper!!)))
        assertFalse("geen PIN-poging gebruikt", d.key.log.any { it.startsWith("pinToken") })
        assertEquals(0, d.key.fingerCount)

        // Hoofdsleutel zonder vinger mét BIO_MAIN-rapport mag wel.
        val main = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports(), knownProfileOf = { Profile.BIO_MAIN })
        assertTrue(main.open(d.key, SetupDriver.bufferOf(d.paper!!)) is FlowOutcome.Ready)
        main.close()
        d.paper!!.fill('\u0000')
    }

    // ---------------------------------------------------------------- YK5 met alwaysUv al aan zonder PIN

    @Test fun yk5MetAlwaysUvZonderPinStoptVoorElkeSchrijfactie() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.yk5_57()).apply { preset(alwaysUvOn = true) }
        val d = SetupDriver(key, Profile.RECOVERY_YK5)
        val s = d.detect() as State.Stopped
        assertEquals(Stop.YK5_ALWAYS_UV_PRESET, s.stop)
        assertTrue(key.writes().isEmpty())
        assertFalse(key.log.any { it.startsWith("makeCredential") })
    }

    // ---------------------------------------------------------------- rapport-import en vergelijkingsbasis

    private val now = Instant.parse("2026-10-12T12:00:00Z")

    private fun store() = ReportStore(Files.createTempDirectory("hs-review").toFile(), clock = { now })

    @Test fun importUitDeToekomstWordtGeweigerd() {
        val st = store()
        val future = ReportFixtures.sample(createdAt = "2027-01-01T00:00:00Z")
        val out = ByteArrayOutputStream()
        st.exportTo(out, future)
        try {
            st.importFrom(ByteArrayInputStream(out.toByteArray()))
            fail("rapport uit de toekomst geaccepteerd")
        } catch (e: ReportSchemaException) {
            // goed
        }
        assertTrue(st.loadAll().reports.isEmpty())
        // Binnen de klokmarge mag wel.
        val nearly = ReportFixtures.sample(createdAt = "2026-10-12T12:05:00Z")
        val out2 = ByteArrayOutputStream()
        st.exportTo(out2, nearly)
        st.importFrom(ByteArrayInputStream(out2.toByteArray()))
        assertEquals(1, st.loadAll().reports.size)
    }

    @Test fun basisAlleenUitHetVerledenEnEigenAppSleutelEerst() {
        val st = store()
        val own = ReportFixtures.hasher
        val foreign = SerialHasher(RawSerialKey(ByteArray(32) { 0x55 }))
        val ownOld = ReportFixtures.sample(createdAt = "2026-07-01T10:00:00Z")
        val foreignNewer = ReportFixtures.sample(createdAt = "2026-09-01T10:00:00Z").copy(serialHmac = foreign.hash(12345678))
        val futureOwn = ReportFixtures.sample(createdAt = "2026-12-01T10:00:00Z")
        listOf(ownOld, foreignNewer, futureOwn).forEach { st.save(it) }

        val b = st.baselineFor(Profile.BIO_MAIN, own.keyId)
        assertEquals("eigen app-sleutel heeft voorrang, toekomst telt niet", ownOld.createdAt, b!!.createdAt)
        assertEquals("zonder eigen keyId: laatste uit het verleden", foreignNewer.createdAt, st.baselineFor(Profile.BIO_MAIN, null)!!.createdAt)
        assertEquals("alleen vreemde: die is basis", foreignNewer.createdAt, st.baselineFor(Profile.BIO_MAIN, "0123456789abcdef")!!.createdAt)
        assertEquals(null, st.baselineFor(Profile.RECOVERY_YK5, own.keyId))
        assertEquals(Profile.BIO_MAIN, st.profileForSerial(ownOld.serialHmac!!))
    }

    @Test fun keuringNegeertBasisUitDeToekomst() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        val setup = (d.runNew() as State.ReportReady).report
        // Geïmporteerd rapport "uit de toekomst" met een ander serienummer.
        val future = setup.copy(createdAt = "2099-01-01T00:00:00Z", serialHmac = KeyProfiles.reportHasher.hash(99999999))
        val k = KeuringFlow(KeyProfiles.inspector(), FakeAttestationJudgeRef.judge, KeyProfiles.reports())
        val out = k.withoutPin(d.key, Profile.BIO_MAIN, future) as FlowOutcome.Done
        assertFalse("basis uit de toekomst telt niet", out.report!!.comparedWithPrevious)
        assertEquals(null, out.stop)
        d.paper!!.fill('\u0000')
    }

    @Test fun inrichtingsrapportIsNieuweBasis() {
        val r = nl.icthorse.horsesafe.report.ReportCompare.asNewBasis(ReportFixtures.sample())
        assertFalse(r.comparedWithPrevious)
        assertEquals(Verdict.GREEN, r.checks.single { it.id == nl.icthorse.horsesafe.report.ReportCompare.CHECK_ID }.verdict)
    }
}

private object FakeAttestationJudgeRef {
    val judge: AttestationJudge = nl.icthorse.horsesafe.flow.fake.FakeAttestationJudge
}
