package nl.icthorse.horsesafe.flow

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.flow.fake.CyclicSource
import nl.icthorse.horsesafe.flow.fake.FakeAttestationJudge
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.flow.fake.SetupDriver
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.report.ReportJsonSchema
import nl.icthorse.horsesafe.yubikey.api.KeyError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Lektest (plan §Tests 4, JVM-deel): een sentinel-PIN door alle flows; daarna mag geen 7-tekenvenster
 * van de PIN voorkomen in State/history.toString, Stop-teksten, meldingen, rapport-JSON,
 * exceptieberichten, System.out/err of bestanden in de tijdelijke map (java.io.tmpdir).
 */
class FlowCanaryTest {

    /** Alleen letters buiten 0-9a-f, zodat hex in rapporten nooit per toeval matcht. */
    private val sentinelSource = intArrayOf(9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 6, 7, 8, 9, 11)

    private fun windows(pin: CharArray): Set<String> = (0..pin.size - 7).map { String(pin, it, 7) }.toSet()

    private fun assertClean(what: String, text: String, w: Set<String>) {
        val hit = w.firstOrNull { it in text }
        assertTrue("PIN-fragment gelekt in $what", hit == null)
    }

    @Test fun sentinelLektNiet() = runBlocking {
        val startedAt = System.currentTimeMillis() - 1000
        val outBuf = ByteArrayOutputStream()
        val errBuf = ByteArrayOutputStream()
        val oldOut = System.out
        val oldErr = System.err
        System.setOut(PrintStream(outBuf, true))
        System.setErr(PrintStream(errBuf, true))
        val texts = mutableListOf<Pair<String, String>>()
        var paper: CharArray? = null
        try {
            // F2 volledig.
            val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN, source = CyclicSource(sentinelSource))
            val end = d.runNew()
            paper = d.paper!!
            assertTrue(end is State.ReportReady)
            texts += "history" to d.machine.history.joinToString()
            texts += "report-json" to ReportJsonSchema.toJson((end as State.ReportReady).report)
            texts += "notice" to d.machine.notice.value.toString()
            texts += "machine" to d.machine.toString()

            // Stop met PIN in het geheugen (attestation faalt na setPin).
            val d2 = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574().copy(genuine = false)), Profile.BIO_MAIN, source = CyclicSource(sentinelSource))
            val s2 = d2.runNew() as State.Stopped
            texts += "stopped" to s2.toString() + s2.stop.tekst + s2.stop.advies

            // Hervatten met foute en juiste PIN.
            val k3 = FakeYubiKey(KeyProfiles.bioFido574()).apply { crashAfter = "setPin" }
            val d3 = SetupDriver(k3, Profile.BIO_MAIN, source = CyclicSource(sentinelSource))
            d3.runNew(); k3.reinsert()
            val r3 = SetupDriver(k3, Profile.BIO_MAIN, SetupMode.RESUME)
            r3.detect()
            r3.send(FlowEvent.PinEntered(SetupDriver.bufferOf(paper.copyOf().also { it[0] = 'x' })))
            texts += "resume-notice" to r3.machine.notice.value.toString()
            val e3 = r3.runResume(paper)
            texts += "resume" to r3.machine.history.joinToString() + e3

            // Keuren, PIN wijzigen, vingers, oefenen.
            val key = d.key
            val k = KeuringFlow(KeyProfiles.inspector(), FakeAttestationJudge, KeyProfiles.reports())
            val kr = k.withPin(key, Profile.BIO_MAIN, SetupDriver.bufferOf(paper), null)
            texts += "keuring" to kr.toString() + ((kr as FlowOutcome.Done).report?.let { ReportJsonSchema.toJson(it) } ?: "")
            texts += "keuring-fout" to k.withPin(key, Profile.BIO_MAIN, SetupDriver.bufferOf(paper.copyOf().also { it[1] = 'x' }), null).toString()
            val ff = FingerFlow(KeyProfiles.inspector(), KeyProfiles.reports())
            texts += "vingers" to ff.open(key, SetupDriver.bufferOf(paper)).toString() + ff.add("L-duim") + ff.close()
            texts += "oefenen" to PracticeFlow().verifyOnKey(key, SetupDriver.bufferOf(paper)).toString()
            val cp = ChangePinFlow(Profile.BIO_MAIN, KeyProfiles.inspector(), KeyProfiles.reports(), PinGenerator(CyclicSource(intArrayOf(21, 22, 23))))
            cp.begin(key); cp.generateNewPin()
            val np = cp.revealNewPin { b -> b.useChars { it.copyOf() } }!!
            cp.confirmRetyped(SetupDriver.bufferOf(np))
            texts += "pin-wijzigen" to cp.submit(SetupDriver.bufferOf(paper)).toString() + cp.toString()

            // Exceptieberichten van de sleutel.
            try { key.ctap { pin.pinToken(SetupDriver.bufferOf(paper), nl.icthorse.horsesafe.yubikey.api.Permission.CM) } } catch (e: Exception) {
                texts += "exceptie" to (e.message ?: "") + e.toString()
            }
        } finally {
            System.setOut(oldOut)
            System.setErr(oldErr)
        }
        val w = windows(paper!!)
        assertTrue("sentinel heeft genoeg unieke vensters", w.size >= 10)
        texts.forEach { (what, t) -> assertClean(what, t, w) }
        assertClean("System.out", outBuf.toString(), w)
        assertClean("System.err", errBuf.toString(), w)
        Stop.entries.forEach { assertClean("Stop.${it.name}", it.tekst + it.advies, w) }
        // Alle KeyError-berichten zijn vaste teksten (A-13).
        listOf(
            KeyError.Disconnected(), KeyError.MultipleKeys(), KeyError.UserActionTimeout(), KeyError.Cancelled(),
            KeyError.PinInvalid(3), KeyError.PinBlocked(), KeyError.PinAuthBlocked(), KeyError.PinPolicyViolation(),
            KeyError.PinNotSet(), KeyError.PinUvAuthTokenRequired(), KeyError.UvInvalid(2), KeyError.UvBlocked(),
            KeyError.OperationDenied(), KeyError.TokenInvalid(), KeyError.Ctap(0x31),
        ).forEach { e -> assertClean("KeyError.${e.javaClass.simpleName}", (e.message ?: "") + e.toString(), w) }
        // Tijdelijke map: geen bestand dat tijdens deze test is geschreven, bevat een PIN-fragment.
        val tmp = File(System.getProperty("java.io.tmpdir") ?: "/tmp")
        tmp.walkTopDown().maxDepth(4)
            .filter { it.isFile && it.lastModified() >= startedAt && it.length() in 1..4_000_000 }
            .forEach { f -> assertClean("tmp:${f.name}", runCatching { f.readText(Charsets.ISO_8859_1) }.getOrDefault(""), w) }
        // SecretBuffer.toString is altijd verborgen.
        assertEquals(nl.icthorse.horsesafe.pin.SecretBuffer.HIDDEN, SetupDriver.bufferOf(paper).toString())
        assertFalse(FlowEvent.PinEntered(SetupDriver.bufferOf(paper)).toString().contains(String(paper, 0, 7)))
    }
}
