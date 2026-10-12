package nl.icthorse.horsesafe.yubikey.api

/** Template-id van een ingeschreven vinger; vergelijking op inhoud (`contentEquals`). Geen geheim. */
class TemplateId(bytes: ByteArray) {
    private val b = bytes.copyOf()
    fun bytes(): ByteArray = b.copyOf()
    val hex: String get() = b.joinToString("") { "%02x".format(it) }
    override fun equals(other: Any?): Boolean = other is TemplateId && other.b.contentEquals(b)
    override fun hashCode(): Int = b.contentHashCode()
    override fun toString(): String = "TemplateId($hex)"
}

/** Ingeschreven vinger. [name] ASCII, lengte in bytes ≤ [SensorFacts.maxFriendlyNameBytes]. */
data class Enrollment(val templateId: TemplateId, val name: String?)

/** `getSensorInfo()`; [maxFriendlyNameBytes] i.p.v. een vaste 15 (kritiek 15). */
data class SensorFacts(
    val fingerprintKind: Int,
    val maxCaptureSamplesRequiredForEnroll: Int,
    val maxFriendlyNameBytes: Int,
)

/** Terugkoppeling per sample (CTAP lastEnrollSampleStatus), met Nederlandse tekst voor M7. */
enum class SampleFeedback(val code: Int, val nl: String) {
    GOOD(0x00, "Goed, til je vinger op en leg hem opnieuw."),
    TOO_HIGH(0x01, "Vinger te hoog."),
    TOO_LOW(0x02, "Vinger te laag."),
    TOO_LEFT(0x03, "Vinger te ver naar links."),
    TOO_RIGHT(0x04, "Vinger te ver naar rechts."),
    TOO_FAST(0x05, "Te snel, houd je vinger iets langer stil."),
    TOO_SLOW(0x06, "Te langzaam."),
    POOR_QUALITY(0x07, "Slechte opname, maak je vinger schoon en droog."),
    TOO_SKEWED(0x08, "Vinger te scheef."),
    TOO_SHORT(0x09, "Te kort aangeraakt."),
    MERGE_FAILURE(0x0A, "Opname paste niet, probeer opnieuw."),
    EXISTS(0x0B, "Deze vinger staat al op de sleutel."),
    NO_USER_ACTIVITY(0x0D, "Geen vinger gevoeld."),
    NO_UP_TRANSITION(0x0E, "Til je vinger helemaal op tussen de opnames."),
    UNKNOWN(-1, "Onbekende melding van de sleutel, probeer opnieuw.");

    companion object {
        fun of(code: Int): SampleFeedback = entries.firstOrNull { it.code == code } ?: UNKNOWN
    }
}

/** Voortgang tijdens [BioEnrollOps.enroll]: na elke sample (ook na een `CaptureError`). */
data class EnrollProgress(val feedback: SampleFeedback, val remaining: Int?)

/**
 * FingerprintBioEnrollment-adapter; alle methodes vragen een [Permission.BE]-token. Alleen voor de
 * hoofdsleutel-Bio (F2.9, F6); de noodsleutel krijgt nooit een vinger.
 */
interface BioEnrollOps {
    suspend fun sensorInfo(token: AuthToken): SensorFacts

    /** Lege lijst bij een lege Bio (yubikit: lege map bij ERR_INVALID_OPTION). */
    suspend fun enumerate(token: AuthToken): List<Enrollment>

    /**
     * Schrijft één vinger in. Vangt `CaptureError` en gaat door (meldt via [onProgress]); bij I/O-fout of
     * coroutine-annulering volgt `cancel()` op de sleutel en daarna [KeyError.Cancelled]/[KeyError.Disconnected].
     */
    suspend fun enroll(token: AuthToken, name: String?, timeoutMs: Int?, onProgress: (EnrollProgress) -> Unit): TemplateId

    suspend fun rename(token: AuthToken, templateId: TemplateId, name: String)

    suspend fun remove(token: AuthToken, templateId: TemplateId)
}
