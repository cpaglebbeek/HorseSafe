package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.flow.fake.KeySpec
import nl.icthorse.horsesafe.flow.fake.SetupDriver
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** F8 Sleutel wissen (0.3.1): bevestiging, zelfde sleutel, resetvenster, aanraking, nalezen. */
class ResetFlowTest {

    private suspend fun configured(spec: KeySpec = KeyProfiles.bioFido574(), profile: Profile = Profile.BIO_MAIN): FakeYubiKey {
        val d = SetupDriver(FakeYubiKey(spec), profile)
        assertTrue(d.runNew() is State.ReportReady)
        d.key.log.clear()
        return d.key
    }

    private fun flow() = ResetFlow(KeyProfiles.inspector())

    private suspend fun readyAndConfirmed(f: ResetFlow, key: FakeYubiKey): ResetOutcome.Ready {
        val r = f.inspect(key) as ResetOutcome.Ready
        assertTrue(f.confirm(r.serialLast4))
        return r
    }

    @Test fun wistIngerichteBio() = runBlocking {
        val key = configured()
        assertNotNull(key.pin)
        assertTrue(key.fingerCount >= 2)
        val f = flow()
        val r = readyAndConfirmed(f, key)
        assertEquals("0001", r.serialLast4)
        assertEquals(true, r.facts.option("clientPin"))
        assertFalse("uitlezen schrijft niets", key.writes().isNotEmpty())
        key.unplug(); key.reinsert()
        val out = f.wipe(key)
        assertTrue("$out", out is ResetOutcome.Wiped)
        assertNull(key.pin)
        assertEquals(0, key.fingerCount)
        assertEquals(4, key.minPinLength)
        assertEquals(listOf("reset"), key.writes())
        assertEquals(false, (out as ResetOutcome.Wiped).facts.option("clientPin"))
        assertFalse("bevestiging is na wissen op", f.isConfirmed)
    }

    @Test fun naWissenOpnieuwInrichten() = runBlocking {
        val key = configured()
        val f = flow()
        readyAndConfirmed(f, key)
        key.reinsert()
        assertTrue(f.wipe(key) is ResetOutcome.Wiped)
        val again = SetupDriver(key, Profile.BIO_MAIN).runNew()
        assertTrue("opnieuw inrichten: $again", again is State.ReportReady)
    }

    @Test fun noodsleutelYk5KrijgtFabrieksstandTerug() = runBlocking {
        val key = configured(KeyProfiles.yk5_57(), Profile.RECOVERY_YK5)
        assertFalse("U2F weg na alwaysUv", "U2F_V2" in key.versions)
        val f = flow()
        readyAndConfirmed(f, key)
        key.reinsert()
        assertTrue(f.wipe(key) is ResetOutcome.Wiped)
        assertEquals(false, key.alwaysUv)
        assertTrue("U2F_V2" in key.versions)
    }

    @Test fun zonderOfMetVerkeerdeBevestigingNietsGewist() = runBlocking {
        val key = configured()
        val f = flow()
        val r = f.inspect(key) as ResetOutcome.Ready
        assertEquals(ResetOutcome.Blocked(Stop.INTERNAL_ERROR), f.wipe(key))
        assertFalse(f.confirm(if (r.serialLast4 == "9999") "0000" else "9999"))
        assertEquals(ResetOutcome.Blocked(Stop.INTERNAL_ERROR), f.wipe(key))
        assertTrue(key.writes().isEmpty())
        assertNotNull(key.pin)
    }

    @Test fun andereSleutelNaInsteken() = runBlocking {
        val a = configured(KeyProfiles.bioFido574(serial = 31000001))
        val b = configured(KeyProfiles.bioFido574(serial = 31000999))
        val f = flow()
        readyAndConfirmed(f, a)
        assertEquals(ResetOutcome.Blocked(Stop.RESET_OTHER_KEY), f.wipe(b))
        assertTrue(b.writes().isEmpty())
        assertNotNull(b.pin)
        assertNotNull(a.pin)
    }

    @Test fun teLaatNaInstekenDanOpnieuw() = runBlocking {
        val key = configured()
        val f = flow()
        readyAndConfirmed(f, key)
        key.closeResetWindow()
        assertEquals(ResetOutcome.Retry(ResetFlow.NOTICE_TOO_LATE), f.wipe(key))
        assertNotNull("niets gewist", key.pin)
        assertTrue("bevestiging blijft geldig", f.isConfirmed)
        key.reinsert()
        assertTrue(f.wipe(key) is ResetOutcome.Wiped)
    }

    @Test fun geenAanraking() = runBlocking {
        val key = configured()
        val f = flow()
        readyAndConfirmed(f, key)
        key.reinsert()
        key.touchResponds = false
        assertEquals(ResetOutcome.Retry(ResetFlow.NOTICE_NO_TOUCH), f.wipe(key))
        assertNotNull(key.pin)
    }

    @Test fun losDirectNaWissenWordtNagelezenBijVolgendePoging() = runBlocking {
        val key = configured()
        val f = flow()
        readyAndConfirmed(f, key)
        key.reinsert()
        key.crashAfter = "reset"
        assertEquals(ResetOutcome.Retry(ResetFlow.NOTICE_LOST), f.wipe(key))
        key.reinsert()
        val out = f.wipe(key)
        assertTrue("$out", out is ResetOutcome.Wiped)
        assertNull(key.pin)
    }

    @Test fun zonderSerienummerGeenWissen() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574().copy(serial = null))
        assertEquals(ResetOutcome.Blocked(Stop.RESET_NO_SERIAL), flow().inspect(key))
        val noMgmt = FakeYubiKey(KeyProfiles.bioFido574().copy(managementAvailable = false))
        assertEquals(ResetOutcome.Blocked(Stop.RESET_NO_SERIAL), flow().inspect(noMgmt))
    }

    @Test fun onbekendeSleutelNiet() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574().copy(aaguid = KeyProfiles.NOT_LISTED))
        assertEquals(ResetOutcome.Blocked(Stop.AAGUID_NOT_ALLOWED), flow().inspect(key))
    }

    @Test fun laatsteVierCijfers() {
        assertEquals("0123", ResetFlow.lastDigits(123))
        assertEquals("5678", ResetFlow.lastDigits(12345678))
        assertEquals("0000", ResetFlow.lastDigits(10000))
    }

    @Test fun uitkomstBevatGeenVolledigSerienummer() = runBlocking {
        val key = FakeYubiKey(KeyProfiles.bioFido574(serial = 31234567))
        val r = flow().inspect(key)
        assertFalse(r.toString().contains("31234567"))
    }

    /** 0.3.3: gemeten op een echte Bio — na wissen (zonder PIN) geen of een ander aantal PIN-pogingen; toch inrichten. */
    @Test fun naWissenInrichtenOokAlsPogingenZonderPinOntbreken() = runBlocking {
        for (without in listOf<Int?>(null, 0, 3)) {
            val key = FakeYubiKey(KeyProfiles.bioFido574().copy(retriesWithoutPin = without))
            assertTrue(SetupDriver(key, Profile.BIO_MAIN).runNew() is State.ReportReady)
            val f = flow()
            readyAndConfirmed(f, key)
            key.reinsert()
            assertTrue(f.wipe(key) is ResetOutcome.Wiped)
            val d = SetupDriver(key, Profile.BIO_MAIN)
            val end = d.runNew()
            assertTrue("pogingen zonder PIN = $without: $end", end is State.ReportReady)
            assertTrue((end as State.ReportReady).report.checks.any { it.id == "gate_pin_retries" && it.verdict == Verdict.ORANGE })
            assertEquals(8, key.pinRetries)
        }
    }
}
