package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Verdict
import nl.icthorse.horsesafe.pin.Alphabet
import nl.icthorse.horsesafe.yubikey.api.FirmwareSource
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyFormFactor
import nl.icthorse.horsesafe.yubikey.api.KeyVariant
import nl.icthorse.horsesafe.yubikey.api.Transport
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * Schema versie 1 van het rapport (A-21, kritiek 9). Eén whitelist voor schrijven én lezen:
 * - elk veld van [Report] staat precies één keer in [FIELDS] (een test bewaakt de gelijkheid met de
 *   property-namen van [Report]);
 * - [toJson] en [fromJson] controleren elk veld op type en formaat; een onbekend, ontbrekend of
 *   dubbel veld, een andere [version] of een fout formaat → [ReportSchemaException];
 * - geheimenwacht: geen enkele vrije tekst mag op een PIN lijken (≥ [PIN_RUN] aaneengesloten tekens
 *   uit het PIN-alfabet, of ≥ 3 groepen van 7 zulke tekens met spatie/streep ertussen).
 *
 * Foutberichten noemen alleen veldnamen en nooit inhoud.
 */
object ReportJsonSchema : ReportSchema {
    override val version: Int = 1

    /** Maximale grootte van één rapport (import via SAF). */
    const val MAX_CHARS: Int = 256 * 1024

    /** Een aaneengesloten reeks van zoveel PIN-alfabettekens in vrije tekst = vermoedelijk een PIN. */
    const val PIN_RUN: Int = 20

    /** Volgorde = volgorde in de JSON-uitvoer. */
    val FIELDS: List<String> = listOf(
        "schemaVersion", "appVersion", "createdAt", "kind", "profile", "transport", "aaguid", "keyClass",
        "variant", "firmware", "firmwareSource", "formFactor", "serialHmac", "versions", "options",
        "rawPresent", "minPinLength", "maxPinLength", "forcePinChange", "pinRetries", "uvRetries",
        "residentCredentials", "fingerCount", "fingerNames", "fingerTemplateHashes", "attestationOk",
        "attestationLeafSha256", "checks", "stop", "sealCode", "paperLocationCode",
        "comparedWithPrevious", "differences",
    )

    override val allowedFields: Set<String> = FIELDS.toSet()

    val RAW_PRESENT_KEYS: List<String> = listOf("0x0C", "0x0D", "0x0E", "0x1D")
    val CHECK_FIELDS: Set<String> = setOf("id", "verdict", "detail")

    /** `keyClass` in het rapport: [KeyClass.jsonName], of `unknown`. */
    fun keyClassName(k: KeyClass): String = k.jsonName ?: "unknown"

    /** `variant` in het rapport: kleine letters. */
    fun variantName(v: KeyVariant): String = v.name.lowercase()

    private val KEY_CLASSES = KeyClass.entries.map { keyClassName(it) }.toSet()
    private val VARIANTS = KeyVariant.entries.map { variantName(it) }.toSet()

    private val RE_APP_VERSION = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}-[A-Za-z]{1,32}(-debug)?$")
    private val RE_CREATED = Regex("^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(\\.\\d{1,9})?Z$")
    private val RE_AAGUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    private val RE_FIRMWARE = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
    private val RE_SHA256 = Regex("^[0-9a-f]{64}$")
    private val RE_VERSION = Regex("^[A-Z0-9_]{1,32}$")
    private val RE_OPTION = Regex("^[A-Za-z][A-Za-z0-9]{0,47}$")
    private val RE_CHECK_ID = Regex("^[a-z0-9_]{1,64}$")
    private val RE_CODE = Regex("^[A-Za-z0-9-]{1,32}$")
    private val RE_DIFF = Regex("^[A-Za-z0-9_.\\[\\]]{1,80}$")
    private val ALPH = "[${Alphabet.CHARS}]"
    private val RE_PIN_RUN = Regex("$ALPH{$PIN_RUN,}")
    private val RE_PIN_GROUPS = Regex("$ALPH{7}(?:[ \\-]$ALPH{7}){2,}")

    // ------------------------------------------------------------------ schrijven

    override fun toJson(report: Report): String {
        val m = LinkedHashMap<String, Any?>()
        m["schemaVersion"] = report.schemaVersion
        m["appVersion"] = report.appVersion
        m["createdAt"] = report.createdAt
        m["kind"] = report.kind.name
        m["profile"] = report.profile.name
        m["transport"] = report.transport
        m["aaguid"] = report.aaguid
        m["keyClass"] = report.keyClass
        m["variant"] = report.variant
        m["firmware"] = report.firmware
        m["firmwareSource"] = report.firmwareSource
        m["formFactor"] = report.formFactor
        m["serialHmac"] = report.serialHmac
        m["versions"] = report.versions
        m["options"] = LinkedHashMap(report.options.toSortedMap())
        m["rawPresent"] = LinkedHashMap(report.rawPresent.toSortedMap())
        m["minPinLength"] = report.minPinLength
        m["maxPinLength"] = report.maxPinLength
        m["forcePinChange"] = report.forcePinChange
        m["pinRetries"] = report.pinRetries
        m["uvRetries"] = report.uvRetries
        m["residentCredentials"] = report.residentCredentials
        m["fingerCount"] = report.fingerCount
        m["fingerNames"] = report.fingerNames
        m["fingerTemplateHashes"] = report.fingerTemplateHashes
        m["attestationOk"] = report.attestationOk
        m["attestationLeafSha256"] = report.attestationLeafSha256
        m["checks"] = report.checks.map { linkedMapOf("id" to it.id, "verdict" to it.verdict.name, "detail" to it.detail) }
        m["stop"] = report.stop
        m["sealCode"] = report.sealCode
        m["paperLocationCode"] = report.paperLocationCode
        m["comparedWithPrevious"] = report.comparedWithPrevious
        m["differences"] = report.differences
        if (m.keys.toList() != FIELDS) throw ReportSchemaException("interne fout: veldenlijst wijkt af van de whitelist")
        // Zelfde controle als bij import: het uitgeschreven rapport moet weer strikt inleesbaar zijn.
        val back = decode(m.mapValues { (_, v) -> normalize(v) })
        if (back != report) throw ReportSchemaException("rapport is niet verliesvrij te serialiseren")
        val json = StrictJson.write(m)
        if (json.length > MAX_CHARS) throw ReportSchemaException("rapport is te groot")
        return json
    }

    /** Int → Long, zoals de lezer getallen teruggeeft. */
    private fun normalize(v: Any?): Any? = when (v) {
        is Int -> v.toLong()
        is Map<*, *> -> v.entries.associate { (k, e) -> k to normalize(e) }
        is List<*> -> v.map { normalize(it) }
        else -> v
    }

    // ------------------------------------------------------------------ lezen

    override fun fromJson(json: String): Report {
        if (json.length > MAX_CHARS) throw ReportSchemaException("rapport is te groot")
        val root = StrictJson.parse(json) as? Map<*, *> ?: throw ReportSchemaException("rapport is geen JSON-object")
        return decode(root)
    }

    private fun decode(root: Map<*, *>): Report {
        val keys = root.keys.map { it as? String ?: throw ReportSchemaException("sleutel is geen string") }.toSet()
        val unknown = keys - allowedFields
        if (unknown.isNotEmpty()) throw ReportSchemaException("onbekend veld: ${unknown.sorted().joinToString { short(it) }}")
        val missing = allowedFields - keys
        if (missing.isNotEmpty()) throw ReportSchemaException("ontbrekend veld: ${missing.sorted().joinToString()}")
        val r = Reader(root)

        val schemaVersion = r.int("schemaVersion", 0..1000)!!
        if (schemaVersion != version) throw ReportSchemaException("schemaversie $schemaVersion wordt niet ondersteund (verwacht $version)")

        val createdAt = r.str("createdAt", RE_CREATED)!!
        try { Instant.parse(createdAt) } catch (e: DateTimeParseException) { throw ReportSchemaException("veld createdAt: geen geldige UTC-tijd") }

        val checksRaw = r.list("checks", 200)!!
        val checks = checksRaw.mapIndexed { i, e ->
            val c = e as? Map<*, *> ?: throw ReportSchemaException("veld checks[$i]: geen object")
            val ck = c.keys.map { it as? String ?: throw ReportSchemaException("veld checks[$i]: sleutel is geen string") }.toSet()
            if (ck != CHECK_FIELDS) throw ReportSchemaException("veld checks[$i]: velden moeten precies id, verdict, detail zijn")
            val id = c["id"] as? String ?: throw ReportSchemaException("veld checks[$i].id: geen string")
            if (!RE_CHECK_ID.matches(id)) throw ReportSchemaException("veld checks[$i].id: ongeldig formaat")
            val verdict = enumOf<Verdict>("checks[$i].verdict", c["verdict"])
            val detail = c["detail"] as? String ?: throw ReportSchemaException("veld checks[$i].detail: geen string")
            if (detail.length > 500 || detail.any { it.code < 0x20 }) throw ReportSchemaException("veld checks[$i].detail: te lang of stuurteken")
            freeText("checks[$i].detail", detail)
            CheckResult(id, verdict, detail)
        }

        val stop = r.nullableStr("stop")?.let { enumOf<Stop>("stop", it).name }

        return Report(
            schemaVersion = schemaVersion,
            appVersion = r.str("appVersion", RE_APP_VERSION)!!,
            createdAt = createdAt,
            kind = enumOf("kind", root["kind"]),
            profile = enumOf<Profile>("profile", root["profile"]),
            transport = enumOf<Transport>("transport", root["transport"]).name,
            aaguid = r.str("aaguid", RE_AAGUID)!!,
            keyClass = r.oneOf("keyClass", KEY_CLASSES),
            variant = r.oneOf("variant", VARIANTS),
            firmware = r.str("firmware", RE_FIRMWARE, nullable = true),
            firmwareSource = enumOf<FirmwareSource>("firmwareSource", root["firmwareSource"]).name,
            formFactor = enumOf<KeyFormFactor>("formFactor", root["formFactor"]).name,
            serialHmac = r.str("serialHmac", SerialHasher.FORMAT, nullable = true),
            versions = r.strList("versions", RE_VERSION, 16)!!,
            options = r.boolMap("options", 64) { k -> RE_OPTION.matches(k) },
            rawPresent = r.boolMap("rawPresent", RAW_PRESENT_KEYS.size) { it in RAW_PRESENT_KEYS }.also {
                if (it.keys != RAW_PRESENT_KEYS.toSet()) throw ReportSchemaException("veld rawPresent: verwacht precies ${RAW_PRESENT_KEYS.joinToString()}")
            },
            minPinLength = r.int("minPinLength", 0..255, nullable = true),
            maxPinLength = r.int("maxPinLength", 0..255, nullable = true),
            forcePinChange = r.bool("forcePinChange", nullable = true),
            pinRetries = r.int("pinRetries", 0..255, nullable = true),
            uvRetries = r.int("uvRetries", 0..255, nullable = true),
            residentCredentials = r.int("residentCredentials", 0..100_000, nullable = true),
            fingerCount = r.int("fingerCount", 0..10, nullable = true),
            fingerNames = r.list("fingerNames", 10, nullable = true)?.mapIndexed { i, e ->
                val n = e as? String ?: throw ReportSchemaException("veld fingerNames[$i]: geen string")
                if (n.isEmpty() || n.length > 64 || n.any { it.code !in 0x20..0x7e }) throw ReportSchemaException("veld fingerNames[$i]: 1-64 tekens ASCII")
                freeText("fingerNames[$i]", n)
                n
            },
            fingerTemplateHashes = r.strList("fingerTemplateHashes", RE_SHA256, 10, nullable = true),
            attestationOk = r.bool("attestationOk", nullable = true),
            attestationLeafSha256 = r.str("attestationLeafSha256", RE_SHA256, nullable = true),
            checks = checks,
            stop = stop,
            sealCode = r.str("sealCode", RE_CODE, nullable = true)?.also { freeText("sealCode", it) },
            paperLocationCode = r.str("paperLocationCode", RE_CODE, nullable = true)?.also { freeText("paperLocationCode", it) },
            comparedWithPrevious = r.bool("comparedWithPrevious")!!,
            differences = r.strList("differences", RE_DIFF, 64)!!,
        ).also { rep ->
            // Overige vrije tekst ook door de geheimenwacht.
            freeText("appVersion", rep.appVersion)
            rep.options.keys.forEach { freeText("options", it) }
            rep.differences.forEach { freeText("differences", it) }
        }
    }

    /** Weigert tekst die op een PIN lijkt. Noemt alleen het veld, nooit de inhoud. */
    private fun freeText(field: String, s: String) {
        if (RE_PIN_RUN.containsMatchIn(s) || RE_PIN_GROUPS.containsMatchIn(s)) {
            throw ReportSchemaException("veld $field: tekst lijkt op een PIN en is geweigerd")
        }
    }

    private fun short(s: String) = if (s.length <= 40) s else s.take(40) + "…"

    private inline fun <reified E : Enum<E>> enumOf(field: String, v: Any?): E {
        val s = v as? String ?: throw ReportSchemaException("veld $field: geen string")
        return enumValues<E>().firstOrNull { it.name == s } ?: throw ReportSchemaException("veld $field: onbekende waarde")
    }

    private class Reader(val m: Map<*, *>) {
        fun str(f: String, re: Regex, nullable: Boolean = false): String? {
            val v = m[f]
            if (v == null) { if (nullable) return null else throw ReportSchemaException("veld $f: mag niet leeg zijn") }
            val s = v as? String ?: throw ReportSchemaException("veld $f: geen string")
            if (!re.matches(s)) throw ReportSchemaException("veld $f: ongeldig formaat")
            return s
        }

        fun nullableStr(f: String): String? {
            val v = m[f] ?: return null
            return v as? String ?: throw ReportSchemaException("veld $f: geen string")
        }

        fun oneOf(f: String, allowed: Set<String>): String {
            val s = m[f] as? String ?: throw ReportSchemaException("veld $f: geen string")
            if (s !in allowed) throw ReportSchemaException("veld $f: onbekende waarde")
            return s
        }

        fun int(f: String, range: IntRange, nullable: Boolean = false): Int? {
            val v = m[f]
            if (v == null) { if (nullable) return null else throw ReportSchemaException("veld $f: mag niet leeg zijn") }
            val l = v as? Long ?: throw ReportSchemaException("veld $f: geen geheel getal")
            if (l < range.first || l > range.last) throw ReportSchemaException("veld $f: buiten bereik")
            return l.toInt()
        }

        fun bool(f: String, nullable: Boolean = false): Boolean? {
            val v = m[f]
            if (v == null) { if (nullable) return null else throw ReportSchemaException("veld $f: mag niet leeg zijn") }
            return v as? Boolean ?: throw ReportSchemaException("veld $f: geen true/false")
        }

        fun list(f: String, max: Int, nullable: Boolean = false): List<*>? {
            val v = m[f]
            if (v == null) { if (nullable) return null else throw ReportSchemaException("veld $f: mag niet leeg zijn") }
            val l = v as? List<*> ?: throw ReportSchemaException("veld $f: geen lijst")
            if (l.size > max) throw ReportSchemaException("veld $f: te veel elementen")
            return l
        }

        fun strList(f: String, re: Regex, max: Int, nullable: Boolean = false): List<String>? =
            list(f, max, nullable)?.mapIndexed { i, e ->
                val s = e as? String ?: throw ReportSchemaException("veld $f[$i]: geen string")
                if (!re.matches(s)) throw ReportSchemaException("veld $f[$i]: ongeldig formaat")
                s
            }

        fun boolMap(f: String, max: Int, keyOk: (String) -> Boolean): Map<String, Boolean> {
            val v = m[f] ?: throw ReportSchemaException("veld $f: mag niet leeg zijn")
            val mm = v as? Map<*, *> ?: throw ReportSchemaException("veld $f: geen object")
            if (mm.size > max) throw ReportSchemaException("veld $f: te veel sleutels")
            val out = LinkedHashMap<String, Boolean>()
            for ((k, b) in mm.entries.sortedBy { it.key as? String }) {
                val ks = k as? String ?: throw ReportSchemaException("veld $f: sleutel is geen string")
                if (!keyOk(ks)) throw ReportSchemaException("veld $f: ongeldige sleutel")
                out[ks] = b as? Boolean ?: throw ReportSchemaException("veld $f: waarde is geen true/false")
            }
            return out
        }
    }
}
