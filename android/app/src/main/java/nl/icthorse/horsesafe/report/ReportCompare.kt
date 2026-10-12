package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Verdict

/**
 * Uitkomst van vorig-vs-nieuw (F4, M9).
 * - [differences]: veldnamen die verschillen; elk verschil is rood.
 * - [notComparable]: velden die niet vergeleken konden worden (oranje), bv. serienummer met een andere
 *   app-sleutel na herinstallatie + import, of zonder serienummer.
 */
data class ReportComparison(
    val previous: Report?,
    val differences: List<String>,
    val notComparable: List<String>,
) {
    val hasBasis: Boolean get() = previous != null
}

object ReportCompare {
    const val CHECK_ID = "vergelijking"
    const val CHECK_ID_PARTIAL = "vergelijking_onvolledig"

    /**
     * Vergelijkt [current] met [previous] (zelfde profiel; de aanroeper kiest het laatste rapport via
     * [ReportStore.latestFor]). Velden die alleen soms gemeten worden (resident credentials, vingers,
     * attestation-leaf, pogingen) tellen alleen als ze in beide rapporten gemeten zijn.
     */
    fun compare(previous: Report?, current: Report): ReportComparison {
        if (previous == null) return ReportComparison(null, emptyList(), emptyList())
        val diff = mutableListOf<String>()
        val nc = mutableListOf<String>()

        fun always(name: String, a: Any?, b: Any?) { if (a != b) diff += name }
        fun ifBoth(name: String, a: Any?, b: Any?) { if (a != null && b != null && a != b) diff += name }

        always("profile", previous.profile, current.profile)
        always("aaguid", previous.aaguid, current.aaguid)
        always("keyClass", previous.keyClass, current.keyClass)
        always("variant", previous.variant, current.variant)
        always("firmware", previous.firmware, current.firmware)
        always("formFactor", previous.formFactor, current.formFactor)
        always("versions", previous.versions.sorted(), current.versions.sorted())
        (previous.options.keys + current.options.keys).sorted().forEach { k ->
            if (previous.options[k] != current.options[k]) diff += "options.$k"
        }
        (previous.rawPresent.keys + current.rawPresent.keys).sorted().forEach { k ->
            if (previous.rawPresent[k] != current.rawPresent[k]) diff += "rawPresent.$k"
        }
        always("minPinLength", previous.minPinLength, current.minPinLength)
        always("maxPinLength", previous.maxPinLength, current.maxPinLength)
        always("forcePinChange", previous.forcePinChange, current.forcePinChange)

        // Serienummer (HMAC).
        val ps = previous.serialHmac
        val cs = current.serialHmac
        when {
            ps == null && cs == null -> nc += "serialHmac"
            ps != null && cs == null -> diff += "serialHmac"
            ps == null && cs != null -> nc += "serialHmac"
            SerialHasher.keyIdOf(ps!!) != SerialHasher.keyIdOf(cs!!) -> nc += "serialHmac"
            ps != cs -> diff += "serialHmac"
        }

        ifBoth("pinRetries", previous.pinRetries, current.pinRetries)
        ifBoth("uvRetries", previous.uvRetries, current.uvRetries)
        ifBoth("residentCredentials", previous.residentCredentials, current.residentCredentials)
        ifBoth("fingerCount", previous.fingerCount, current.fingerCount)
        ifBoth("fingerNames", previous.fingerNames?.sorted(), current.fingerNames?.sorted())
        ifBoth("fingerTemplateHashes", previous.fingerTemplateHashes?.sorted(), current.fingerTemplateHashes?.sorted())
        ifBoth("attestationLeafSha256", previous.attestationLeafSha256, current.attestationLeafSha256)

        return ReportComparison(previous, diff, nc)
    }

    /**
     * Inrichtingsrapport (SETUP, RESUME): geen vergelijking met een eerder rapport van hetzelfde profiel,
     * want dat hoort meestal bij een andere sleutel (eerst de testsleutel, daarna de echte). Het rapport
     * wordt de nieuwe vergelijkingsbasis.
     */
    fun asNewBasis(current: Report): Report {
        val kept = current.checks.filterNot { it.id == CHECK_ID || it.id == CHECK_ID_PARTIAL }
        val line = CheckResult(CHECK_ID, Verdict.GREEN, "Nieuwe vergelijkingsbasis: de volgende keuring van deze sleutel wordt hiermee vergeleken.")
        return current.copy(comparedWithPrevious = false, differences = emptyList(), checks = kept + line)
    }

    /**
     * Zet [Report.comparedWithPrevious] en [Report.differences] en voegt één regel aan [Report.checks] toe:
     * rood bij verschillen, oranje zonder vergelijkingsbasis (kritiek 9) of bij een onvolledige vergelijking,
     * anders groen. Bestaande regels met dezelfde id worden vervangen.
     */
    fun apply(current: Report, previous: Report?): Report {
        val c = compare(previous, current)
        val extra = mutableListOf<CheckResult>()
        when {
            !c.hasBasis -> extra += CheckResult(CHECK_ID, Verdict.ORANGE, "Geen vergelijkingsbasis: er is geen eerder rapport voor dit profiel.")
            c.differences.isNotEmpty() -> extra += CheckResult(CHECK_ID, Verdict.RED, "Verschilt van het vorige rapport: ${c.differences.joinToString(", ")}.")
            else -> extra += CheckResult(CHECK_ID, Verdict.GREEN, "Gelijk aan het vorige rapport (${c.previous!!.createdAt}).")
        }
        if (c.notComparable.isNotEmpty()) {
            extra += CheckResult(
                CHECK_ID_PARTIAL, Verdict.ORANGE,
                "Niet te vergelijken: ${c.notComparable.joinToString(", ")} (geen serienummer of andere app-sleutel na herinstallatie).",
            )
        }
        val kept = current.checks.filterNot { it.id == CHECK_ID || it.id == CHECK_ID_PARTIAL }
        return current.copy(comparedWithPrevious = c.hasBasis, differences = c.differences, checks = kept + extra)
    }
}
