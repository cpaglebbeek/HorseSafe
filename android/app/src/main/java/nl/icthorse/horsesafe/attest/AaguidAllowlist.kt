package nl.icthorse.horsesafe.attest

import java.security.MessageDigest
import nl.icthorse.horsesafe.report.ReportSchemaException
import nl.icthorse.horsesafe.report.StrictJson
import nl.icthorse.horsesafe.yubikey.AaguidEntry
import nl.icthorse.horsesafe.yubikey.AaguidLookup
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyVariant

/** `aaguids.json` is onleesbaar of wijkt af van de verwachte SHA-256 (fail-closed). */
class AllowlistException(message: String) : Exception(message)

/**
 * AAGUID-allowlist uit de bytes van `assets/trust/aaguids.json` (zelfde bestand als de server,
 * `backend/data/aaguids.json`, FIDO MDS3). `attest/` leest zelf geen bestanden (A-16): de app-laag geeft
 * de bytes en `BuildConfig.AAGUIDS_SHA256` door.
 *
 * Klasse: veld `class` = `bio` of `yubikey5`; elke andere waarde telt als niet toegestaan (zoals op de
 * server). Variant, omdat de server-json de Multi-protocol Bio's gewoon als `bio` voert:
 * - een expliciet veld `variant` (`fido`/`mpe`, gepland in `build_aaguids.py`) wordt gelezen;
 * - daarnaast geldt een omschrijving met "Multi-protocol" altijd als [KeyVariant.MPE] (conservatief:
 *   MPE wint als een van beide het zegt);
 * - `bio` met "FIDO Edition" in de omschrijving = [KeyVariant.FIDO]; `bio` zonder aanwijzing = UNKNOWN;
 * - `yubikey5` = [KeyVariant.FIDO]: de YubiKey 5 deelt geen PIN tussen PIV en FIDO2, dus de 8-tekengrens
 *   van de Bio MPE speelt daar niet.
 *
 * In de app heet een Bio-MPE [APP_CLASS_BIO_MPE] (`bio_mpe`), zie [appClass].
 */
class AaguidAllowlist private constructor(
    private val entries: Map<Aaguid, AaguidEntry>,
    /** SHA-256 (kleine-letter-hex) van de json-bytes, voor M12. Leeg bij [EMPTY]. */
    val sha256Hex: String,
    /** `mds_no` uit het bestand, of null. */
    val mdsNo: Long?,
) : AaguidLookup {

    val size: Int get() = entries.size

    /** null = niet op de lijst → [KeyClass.UNKNOWN] → STOP. */
    override fun lookup(aaguid: Aaguid): AaguidEntry? = entries[aaguid]

    /** `bio`, `bio_mpe` of `yubikey5`; null = niet toegestaan. */
    fun appClass(aaguid: Aaguid): String? = lookup(aaguid)?.let { appClassOf(it) }

    /** Alle AAGUID's met [KeyVariant.MPE] (voor tests en M2). */
    fun mpeAaguids(): Set<Aaguid> = entries.filterValues { it.variant == KeyVariant.MPE }.keys

    override fun toString(): String = "AaguidAllowlist(size=$size, mdsNo=$mdsNo)"

    companion object {
        const val APP_CLASS_BIO_MPE = "bio_mpe"

        val EMPTY = AaguidAllowlist(emptyMap(), "", null)

        fun appClassOf(e: AaguidEntry): String? = when (e.keyClass) {
            KeyClass.BIO -> if (e.variant == KeyVariant.MPE) APP_CLASS_BIO_MPE else KeyClass.BIO.jsonName
            KeyClass.YUBIKEY5 -> KeyClass.YUBIKEY5.jsonName
            KeyClass.UNKNOWN -> null
        }

        /**
         * @throws AllowlistException bij een afwijkende hash, ongeldige JSON, een ongeldige AAGUID-sleutel,
         *   een dubbele AAGUID of een kapotte structuur.
         */
        fun fromJson(json: ByteArray, expectedSha256Hex: String? = null): AaguidAllowlist {
            val hash = TrustRoots.sha256Hex(json)
            if (expectedSha256Hex != null && !MessageDigest.isEqual(
                    hash.toByteArray(Charsets.US_ASCII),
                    expectedSha256Hex.lowercase().toByteArray(Charsets.US_ASCII),
                )
            ) {
                throw AllowlistException("SHA-256 van de AAGUID-lijst wijkt af")
            }
            val text = try {
                json.decodeToString(throwOnInvalidSequence = true)
            } catch (e: CharacterCodingException) {
                throw AllowlistException("AAGUID-lijst is geen UTF-8")
            }
            val root = try {
                StrictJson.parse(text.removePrefix("\uFEFF"))
            } catch (e: ReportSchemaException) {
                throw AllowlistException("AAGUID-lijst is geen geldige JSON")
            }
            val obj = root as? Map<*, *> ?: throw AllowlistException("AAGUID-lijst: geen object")
            val list = obj["aaguids"] as? Map<*, *> ?: throw AllowlistException("AAGUID-lijst: 'aaguids' moet een object zijn")
            val out = LinkedHashMap<Aaguid, AaguidEntry>()
            for ((k, v) in list) {
                val key = (k as? String)?.lowercase() ?: throw AllowlistException("AAGUID-lijst: sleutel geen string")
                val aaguid = try {
                    Aaguid(key)
                } catch (e: IllegalArgumentException) {
                    throw AllowlistException("AAGUID-lijst: ongeldige AAGUID")
                }
                val m = v as? Map<*, *> ?: throw AllowlistException("AAGUID-lijst: item geen object")
                val description = m["description"] as? String
                val keyClass = when (m["class"]) {
                    KeyClass.BIO.jsonName -> KeyClass.BIO
                    KeyClass.YUBIKEY5.jsonName -> KeyClass.YUBIKEY5
                    else -> null
                } ?: continue // onbekende klasse = niet toegestaan (zoals de server)
                val entry = AaguidEntry(keyClass, variantOf(keyClass, m["variant"] as? String, description), description)
                if (out.put(aaguid, entry) != null) throw AllowlistException("AAGUID-lijst: dubbele AAGUID")
            }
            val mdsNo = obj["mds_no"] as? Long
            return AaguidAllowlist(out, hash, mdsNo)
        }

        internal fun variantOf(keyClass: KeyClass, explicit: String?, description: String?): KeyVariant {
            val d = description?.lowercase() ?: ""
            val mpe = explicit?.lowercase() == "mpe" || d.contains("multi-protocol") || d.contains("multi protocol")
            if (mpe) return KeyVariant.MPE
            return when {
                explicit?.lowercase() == "fido" -> KeyVariant.FIDO
                keyClass == KeyClass.YUBIKEY5 -> KeyVariant.FIDO
                d.contains("fido edition") -> KeyVariant.FIDO
                else -> KeyVariant.UNKNOWN
            }
        }
    }
}
