package nl.icthorse.horsesafe.flow

import java.time.Instant
import java.time.temporal.ChronoUnit
import nl.icthorse.horsesafe.report.Report
import nl.icthorse.horsesafe.report.ReportHashes
import nl.icthorse.horsesafe.report.ReportJsonSchema
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.report.SerialHasher
import nl.icthorse.horsesafe.yubikey.api.Enrollment
import nl.icthorse.horsesafe.yubikey.api.KeyFacts

/** Gemeten extra's die niet in [KeyFacts] staan. */
data class Measured(
    val residentCredentials: Int? = null,
    val fingers: List<Enrollment>? = null,
    val attestationOk: Boolean? = null,
    val attestationLeafSha256: String? = null,
    val stop: Stop? = null,
)

/**
 * Bouwt een [Report] uit niet-geheime feiten (A-21): nooit PIN, token of ruw serienummer. Een
 * serienummer-HMAC in een ander formaat dan het rapportschema verwacht gaat niet mee (oranje regel).
 */
class ReportFactory(
    private val appVersion: String,
    private val clock: () -> Instant = { Instant.now() },
) {
    fun build(kind: ReportKind, profile: Profile, facts: KeyFacts, checks: List<CheckResult>, m: Measured = Measured()): Report {
        val serial = facts.serialHmac?.takeIf { SerialHasher.FORMAT.matches(it) }
        val extra = if (facts.serialHmac != null && serial == null) {
            listOf(CheckResult("serienummer_formaat", Verdict.ORANGE, "Serienummer-HMAC in onbekend formaat; niet in het rapport opgenomen."))
        } else emptyList()
        val fingers = m.fingers
        return Report(
            schemaVersion = ReportJsonSchema.version,
            appVersion = appVersion,
            createdAt = clock().truncatedTo(ChronoUnit.SECONDS).toString(),
            kind = kind,
            profile = profile,
            transport = facts.transport.name,
            aaguid = facts.aaguid.uuid,
            keyClass = ReportJsonSchema.keyClassName(facts.keyClass),
            variant = ReportJsonSchema.variantName(facts.variant),
            firmware = facts.firmware?.toString(),
            firmwareSource = facts.firmwareSource.name,
            formFactor = facts.formFactor.name,
            serialHmac = serial,
            versions = facts.versions,
            options = facts.options,
            rawPresent = mapOf(
                "0x0C" to facts.rawPresent.forcePinChange0x0C,
                "0x0D" to facts.rawPresent.minPinLength0x0D,
                "0x0E" to facts.rawPresent.firmwareVersion0x0E,
                "0x1D" to facts.rawPresent.maxPinLength0x1D,
            ),
            minPinLength = if (facts.rawPresent.minPinLength0x0D) facts.minPinLength else null,
            maxPinLength = facts.maxPinLength,
            forcePinChange = facts.forcePinChange,
            pinRetries = facts.pinRetries,
            uvRetries = facts.uvRetries,
            residentCredentials = m.residentCredentials,
            fingerCount = fingers?.size,
            fingerNames = fingers?.mapNotNull { it.name },
            fingerTemplateHashes = fingers?.map { ReportHashes.templateHash(it.templateId) },
            attestationOk = m.attestationOk,
            attestationLeafSha256 = m.attestationLeafSha256,
            checks = dedupe(checks + extra),
            stop = m.stop?.name,
            sealCode = null,
            paperLocationCode = null,
            comparedWithPrevious = false,
            differences = emptyList(),
        )
    }

    /** Laatste regel per id wint (bijv. eindinspectie na detectie). */
    private fun dedupe(checks: List<CheckResult>): List<CheckResult> {
        val m = LinkedHashMap<String, CheckResult>()
        checks.forEach { m.remove(it.id); m[it.id] = it }
        return m.values.toList()
    }
}
