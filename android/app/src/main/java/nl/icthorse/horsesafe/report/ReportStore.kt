package nl.icthorse.horsesafe.report

import android.content.Context
import nl.icthorse.horsesafe.flow.Profile
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.time.Duration
import java.time.Instant

/**
 * Rapporten in app-privéopslag (A-14: `noBackupFilesDir/reports`, geen back-up, geen andere app).
 * Alleen rapporten die door [schema] komen worden geschreven of gelezen; een bestand dat niet aan het
 * schema voldoet wordt overgeslagen en geteld in [Contents.rejected].
 *
 * Export en import via SAF lopen over [exportTo]/[importFrom] (streams van `SafReportIo`), zodat de
 * schemacontrole voor beide richtingen hier zit.
 */
class ReportStore(
    private val dir: File,
    private val schema: ReportSchema = ReportJsonSchema,
    private val clock: () -> Instant = { Instant.now() },
) {
    data class Contents(val reports: List<Report>, val rejected: Int)

    data class ImportResult(val report: Report, val alreadyPresent: Boolean)

    /**
     * Schrijft [report] atomair (tijdelijk bestand + rename). Faalt vóór schrijven als het schema weigert.
     * [replace] = het rapport met dezelfde createdAt, soort en profiel vervangen (aanvulling met de codes
     * van zak en papierlocatie na de automatische bewaring bij het einde van de inrichting).
     */
    @Synchronized
    fun save(report: Report, replace: Boolean = false): File {
        val json = schema.toJson(report)
        ensureDir()
        val base = "${compact(report.createdAt)}-${report.kind.name.lowercase()}-${report.profile.name.lowercase()}"
        var target = File(dir, "$base$SUFFIX")
        var n = 2
        while (!replace && target.exists()) {
            if (target.readText(Charsets.UTF_8) == json) return target
            target = File(dir, "$base-${n++}$SUFFIX")
        }
        val tmp = File(dir, ".${target.name}.tmp")
        tmp.writeText(json, Charsets.UTF_8)
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IOException("rapport kon niet worden opgeslagen")
        }
        return target
    }

    /** Alle geldige rapporten, oudste eerst. */
    @Synchronized
    fun loadAll(): Contents {
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(SUFFIX) && !f.name.startsWith(".") }.orEmpty()
        var rejected = 0
        val reports = files.mapNotNull { f ->
            try {
                if (f.length() > ReportJsonSchema.MAX_CHARS) throw ReportSchemaException("te groot")
                schema.fromJson(decodeUtf8(f.readBytes()))
            } catch (e: ReportSchemaException) {
                rejected++
                null
            } catch (e: IOException) {
                rejected++
                null
            }
        }
        return Contents(reports.sortedWith(compareBy({ it.createdAt }, { it.kind.name })), rejected)
    }

    /** Laatste rapport voor [profile] (één sleutel per profiel), of null = geen vergelijkingsbasis. */
    fun latestFor(profile: Profile, before: String? = null): Report? =
        loadAll().reports.filter { it.profile == profile && (before == null || it.createdAt < before) }.lastOrNull()

    /**
     * Vergelijkingsbasis voor [profile] (F4, review-bevinding import): alleen rapporten van vóór [before]
     * (standaard nu), zodat een rapport "uit de toekomst" nooit voorgoed de basis blijft. Voorrang heeft
     * het laatste rapport waarvan de serial-HMAC met de eigen app-sleutel ([ownKeyId]) is gemaakt; een
     * rapport met een vreemde of geen app-sleutel is alleen basis als er geen eigen rapport is. Dan meldt
     * [ReportCompare] het serienummer als "niet vergelijkbaar" (oranje).
     */
    fun baselineFor(profile: Profile, ownKeyId: String?, before: String = nowIso()): Report? {
        val candidates = loadAll().reports.filter { it.profile == profile && it.createdAt < before }
        if (ownKeyId != null) {
            candidates.lastOrNull { r -> r.serialHmac?.let(SerialHasher::keyIdOf) == ownKeyId }?.let { return it }
        }
        return candidates.lastOrNull()
    }

    /** Profiel van het laatste rapport met deze serial-HMAC (F6: is dit de hoofdsleutel?), of null. */
    fun profileForSerial(serialHmac: String): Profile? =
        loadAll().reports.lastOrNull { it.serialHmac == serialHmac }?.profile

    private fun nowIso(): String = clock().plusSeconds(1).truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString()

    /** Schrijft [report] als JSON naar [out] (SAF-export). Sluit [out] niet. */
    fun exportTo(out: OutputStream, report: Report) {
        out.write(schema.toJson(report).toByteArray(Charsets.UTF_8))
        out.flush()
    }

    /**
     * Leest één rapport uit [input] (SAF-import, kritiek 9), strikt via het schema, en bewaart het in de
     * app-privéopslag. Weigert meer dan [ReportJsonSchema.MAX_CHARS] bytes en ongeldige UTF-8.
     */
    fun importFrom(input: InputStream): ImportResult {
        val bytes = readBounded(input, ReportJsonSchema.MAX_CHARS)
        val report = schema.fromJson(decodeUtf8(bytes))
        val created = try {
            Instant.parse(report.createdAt)
        } catch (e: RuntimeException) {
            throw ReportSchemaException("veld createdAt: geen geldige UTC-tijd")
        }
        if (created.isAfter(clock().plus(IMPORT_CLOCK_SKEW))) {
            throw ReportSchemaException("rapport ligt in de toekomst")
        }
        val json = schema.toJson(report)
        val present = loadAll().reports.any { schema.toJson(it) == json }
        if (!present) save(report)
        return ImportResult(report, present)
    }

    private fun ensureDir() {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("map voor rapporten kon niet worden gemaakt")
    }

    companion object {
        const val SUFFIX = ".horsesafe-report.json"
        const val MIME_TYPE = "application/json"

        /** Marge voor klokverschil tussen toestellen bij import. */
        val IMPORT_CLOCK_SKEW: Duration = Duration.ofMinutes(10)

        /** App-privé, zonder back-up. */
        fun forContext(context: Context): ReportStore = ReportStore(File(context.noBackupFilesDir, "reports"))

        /** Voorstel voor de SAF-bestandsnaam. Bevat geen serienummer of HMAC. */
        fun suggestedFileName(report: Report): String =
            "horsesafe-${report.profile.name.lowercase()}-${report.kind.name.lowercase()}-${compact(report.createdAt)}$SUFFIX"

        private fun compact(iso: String): String = iso.filter { it.isLetterOrDigit() }

        internal fun readBounded(input: InputStream, max: Int): ByteArray {
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                if (out.size() + n > max) throw ReportSchemaException("rapport is te groot")
                out.write(buf, 0, n)
            }
            return out.toByteArray()
        }

        internal fun decodeUtf8(bytes: ByteArray): String = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
        } catch (e: CharacterCodingException) {
            throw ReportSchemaException("rapport is geen geldige UTF-8")
        }
    }
}
