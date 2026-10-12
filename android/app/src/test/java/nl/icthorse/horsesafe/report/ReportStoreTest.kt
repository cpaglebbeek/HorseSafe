package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.Verdict
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files

class ReportStoreTest {
    private val dir: File = Files.createTempDirectory("hs-reports").toFile()
    private val store = ReportStore(File(dir, "reports"))

    @After fun opruimen() { dir.deleteRecursively() }

    @Test fun opslaanLezenEnLaatste() {
        assertNull(store.latestFor(Profile.BIO_MAIN))
        val a = ReportFixtures.sample("2026-10-01T10:00:00Z")
        val b = ReportFixtures.sample("2026-10-12T10:00:00Z")
        val c = ReportFixtures.sample("2026-10-05T10:00:00Z", profile = Profile.RECOVERY_YK5).copy(keyClass = "yubikey5")
        listOf(b, a, c).forEach { store.save(it) }
        store.save(a) // identiek → geen tweede bestand
        val all = store.loadAll()
        assertEquals(3, all.reports.size)
        assertEquals(0, all.rejected)
        assertEquals(b, store.latestFor(Profile.BIO_MAIN))
        assertEquals(a, store.latestFor(Profile.BIO_MAIN, before = b.createdAt))
        assertEquals(c, store.latestFor(Profile.RECOVERY_YK5))
        File(dir, "reports").listFiles()!!.forEach { assertTrue(it.name, it.name.endsWith(ReportStore.SUFFIX)) }
    }

    @Test fun ongeldigBestandWordtOvergeslagen() {
        store.save(ReportFixtures.sample())
        File(dir, "reports/x${ReportStore.SUFFIX}").writeText("{\"schemaVersion\":1,\"pin\":\"x\"}")
        val all = store.loadAll()
        assertEquals(1, all.reports.size)
        assertEquals(1, all.rejected)
    }

    @Test fun exportEnImport() {
        val r = ReportFixtures.sample()
        val out = ByteArrayOutputStream()
        store.exportTo(out, r)
        val other = ReportStore(File(dir, "andere-telefoon"))
        val res = other.importFrom(ByteArrayInputStream(out.toByteArray()))
        assertEquals(r, res.report)
        assertFalse(res.alreadyPresent)
        assertTrue(other.importFrom(ByteArrayInputStream(out.toByteArray())).alreadyPresent)
        assertEquals(1, other.loadAll().reports.size)
    }

    @Test fun importWeigertSchemafout() {
        val bad = ReportJsonSchema.toJson(ReportFixtures.sample()).dropLast(1) + ",\"serial\":1}"
        listOf(bad.toByteArray(), byteArrayOf(0xC3.toByte(), 0x28), ByteArray(ReportJsonSchema.MAX_CHARS + 1) { ' '.code.toByte() }).forEach {
            try { store.importFrom(ByteArrayInputStream(it)); fail() } catch (e: ReportSchemaException) { }
        }
        assertEquals(0, store.loadAll().reports.size)
    }

    @Test fun bestandsnaamZonderSerienummer() {
        val r = ReportFixtures.sample()
        val n = ReportStore.suggestedFileName(r)
        assertEquals("horsesafe-bio_main-setup-20261012T100000Z.horsesafe-report.json", n)
        assertFalse(n.contains(r.serialHmac!!.take(8)))
    }
}

class ReportCompareTest {
    private val prev = ReportFixtures.sample("2026-07-01T10:00:00Z")

    @Test fun geenBasisIsOranje() {
        val out = ReportCompare.apply(ReportFixtures.sample(), null)
        assertFalse(out.comparedWithPrevious)
        assertEquals(Verdict.ORANGE, out.checks.single { it.id == ReportCompare.CHECK_ID }.verdict)
    }

    @Test fun gelijkIsGroen() {
        val out = ReportCompare.apply(ReportFixtures.sample(), prev)
        assertTrue(out.comparedWithPrevious)
        assertEquals(emptyList<String>(), out.differences)
        assertEquals(Verdict.GREEN, out.checks.single { it.id == ReportCompare.CHECK_ID }.verdict)
        ReportJsonSchema.toJson(out)
    }

    @Test fun verschillenZijnRood() {
        val cur = ReportFixtures.sample(serial = 99999999).copy(
            firmware = "5.7.2",
            pinRetries = 7,
            options = prev.options + ("alwaysUv" to false),
            fingerNames = listOf("R-wijs", "R-duim"),
        )
        val out = ReportCompare.apply(cur, prev)
        assertEquals(listOf("firmware", "options.alwaysUv", "serialHmac", "pinRetries", "fingerNames"), out.differences)
        assertEquals(Verdict.RED, out.checks.single { it.id == ReportCompare.CHECK_ID }.verdict)
        ReportJsonSchema.toJson(out)
    }

    @Test fun andereAppSleutelIsNietVergelijkbaar() {
        val otherHasher = SerialHasher(RawSerialKey(ByteArray(32) { 7 }))
        val cur = ReportFixtures.sample().copy(serialHmac = otherHasher.hash(12345678))
        assertNotEquals(prev.serialHmac, cur.serialHmac)
        val c = ReportCompare.compare(prev, cur)
        assertEquals(emptyList<String>(), c.differences)
        assertEquals(listOf("serialHmac"), c.notComparable)
        val out = ReportCompare.apply(cur, prev)
        assertEquals(Verdict.ORANGE, out.checks.single { it.id == ReportCompare.CHECK_ID_PARTIAL }.verdict)
    }

    @Test fun serienummerVerdwenenIsRood() {
        val cur = ReportFixtures.sample(serial = null)
        assertEquals(listOf("serialHmac"), ReportCompare.compare(prev, cur).differences)
    }

    @Test fun nietGemetenVeldenTellenNiet() {
        val cur = ReportFixtures.sample().copy(kind = ReportKind.KEURING_ZONDER_PIN, residentCredentials = null, fingerNames = null, fingerTemplateHashes = null, attestationLeafSha256 = null)
        assertEquals(emptyList<String>(), ReportCompare.compare(prev, cur).differences)
    }

    @Test fun serialHmac() {
        val h = ReportFixtures.hasher
        assertEquals(h.hash(1), h.hash(1))
        assertNotEquals(h.hash(1), h.hash(2))
        assertNull(h.hash(null))
        assertTrue(SerialHasher.FORMAT.matches(h.hash(1)!!))
        assertEquals(h.keyId, SerialHasher.keyIdOf(h.hash(1)!!))
        assertFalse(h.hash(12345678)!!.contains("12345678"))
    }
}
