package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Profile

/** Soort rapport. */
enum class ReportKind { SETUP, RESUME, KEURING_ZONDER_PIN, KEURING_MET_PIN, PIN_CHANGE, FINGERS }

/**
 * Rapport zonder geheimen (A-21): nooit PIN, tokens, pinUvAuthParam, sharedSecret, credentialId,
 * publieke sleutel of ruw serienummer. Alleen de velden hieronder; [ReportSchema] faalt op elk ander
 * veld (ook bij import via SAF, kritiek 9).
 */
data class Report(
    val schemaVersion: Int,
    /** versionName van de app, bv. `0.3.0-Miller`. */
    val appVersion: String,
    /** ISO-8601 UTC, bv. `2026-10-12T10:00:00Z`. */
    val createdAt: String,
    val kind: ReportKind,
    val profile: Profile,
    /** `USB` / `NFC`. */
    val transport: String,
    val aaguid: String,
    /** `bio` / `yubikey5`. */
    val keyClass: String,
    /** `fido` / `mpe` / `unknown`. */
    val variant: String,
    val firmware: String?,
    val firmwareSource: String,
    val formFactor: String,
    /** HMAC van het serienummer (kritiek 8); null = niet beschikbaar (expliciet gemeld in [checks]). */
    val serialHmac: String?,
    val versions: List<String>,
    val options: Map<String, Boolean>,
    /** Aanwezigheid ruwe getInfo-sleutels: `0x0C`, `0x0D`, `0x0E`, `0x1D` → true/false. */
    val rawPresent: Map<String, Boolean>,
    val minPinLength: Int?,
    val maxPinLength: Int?,
    val forcePinChange: Boolean?,
    val pinRetries: Int?,
    val uvRetries: Int?,
    /** Alleen bij keuren met PIN / inrichten. */
    val residentCredentials: Int?,
    val fingerCount: Int?,
    /** Vingernamen zoals op de sleutel (bv. `R-wijs`). */
    val fingerNames: List<String>?,
    /** SHA-256 (hex) per template-id, tweede identiteitsanker (kritiek 8). */
    val fingerTemplateHashes: List<String>?,
    /** null = niet uitgevoerd. */
    val attestationOk: Boolean?,
    /** SHA-256 (hex) van het leaf-certificaat (batchcertificaat, geen identificatie). */
    val attestationLeafSha256: String?,
    val checks: List<CheckResult>,
    /** Naam van de [nl.icthorse.horsesafe.flow.Stop], of null. */
    val stop: String?,
    /** Code van de verzegelde zak, door Christian ingevoerd (alleen noodsleutel). */
    val sealCode: String?,
    /** Code van de papierlocatie, door Christian ingevoerd. */
    val paperLocationCode: String?,
    /** false = geen vorig rapport → M9 toont "geen vergelijkingsbasis" (oranje). */
    val comparedWithPrevious: Boolean,
    /** Verschillen met het vorige rapport (veldnamen); elk verschil is rood. */
    val differences: List<String>,
)

/** Rapport voldoet niet aan [ReportSchema]: onbekend of ontbrekend veld, verkeerd type of schemaversie. */
class ReportSchemaException(message: String) : Exception(message)
