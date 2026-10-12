package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Verdict
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.pin.RandomSource
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test

/** Een sentinel-PIN mag nooit in rapport-JSON belanden (A-21, plan test 4). */
class ReportCanaryTest {
    private val sentinel: String = run {
        var i = 0
        val pin = PinGenerator(RandomSource { (i++ * 7 + 3) % it }).generate()
        val s = StringBuilder().also { sb -> pin.useChars { a -> a.forEach { sb.append(it) } } }.toString()
        pin.wipe()
        s
    }
    private val grouped = sentinel.chunked(7).joinToString(" ")
    private val r = ReportFixtures.sample()

    private fun refused(report: Report) {
        try {
            val json = ReportJsonSchema.toJson(report)
            fail("rapport met sentinel geaccepteerd (lengte ${json.length})")
        } catch (e: ReportSchemaException) {
            assertFalse("foutbericht bevat geen PIN", e.message.orEmpty().contains(sentinel.take(10)))
        }
    }

    @Test fun normaalRapportBevatGeenSentinel() {
        val json = ReportJsonSchema.toJson(r)
        assertFalse(json.contains(sentinel))
        sentinel.chunked(7).forEach { assertFalse(json.contains(it)) }
    }

    @Test fun sentinelInVrijeTekstWordtGeweigerd() {
        refused(r.copy(checks = r.checks + CheckResult("lek", Verdict.RED, "PIN: $sentinel")))
        refused(r.copy(checks = r.checks + CheckResult("lek", Verdict.RED, "PIN: $grouped")))
        refused(r.copy(checks = r.checks + CheckResult("lek", Verdict.RED, sentinel.substring(5, 5 + ReportJsonSchema.PIN_RUN))))
        refused(r.copy(fingerNames = listOf(sentinel.take(40))))
        refused(r.copy(sealCode = sentinel.take(30)))
        refused(r.copy(paperLocationCode = sentinel.take(25)))
        refused(r.copy(differences = listOf(sentinel)))
        refused(r.copy(options = r.options + (sentinel.take(40) to true)))
    }

    @Test fun sentinelBijImportWordtGeweigerd() {
        val json = ReportJsonSchema.toJson(r).replace("FIDO 2.1 aanwezig.", "PIN $grouped")
        try { ReportJsonSchema.fromJson(json); fail() } catch (e: ReportSchemaException) {
            assertFalse(e.message.orEmpty().contains(sentinel.take(7)))
        }
    }

    @Test fun nederlandseTekstWordtNietGeweigerd() {
        val teksten = listOf(
            "Gelijk aan het vorige rapport (2026-10-12T10:00:00Z).",
            "Verschilt van het vorige rapport: firmware, serialHmac, options.alwaysUv.",
            "U2F_V2 staat nog in versions na alwaysUv; afwijkend, vastgelegd.",
            "Minimale PIN-lengte 63 teruggelezen; maxPINLength 63; forcePINChange false.",
            "Vingerafdrukken: 2 ingeschreven, verwachte bereik 2-3. Attestation packed, keten geldig.",
        )
        ReportJsonSchema.toJson(r.copy(checks = teksten.mapIndexed { i, t -> CheckResult("t$i", Verdict.GREEN, t) }))
        // Controletekens zijn ook geheim, maar 9 losse tekens zijn geen herkenbaar patroon; hier alleen de PIN.
        GroupCheck.GROUPS
    }
}
