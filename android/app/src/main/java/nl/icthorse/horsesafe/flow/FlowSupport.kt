package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.CancellationException
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.AttestationEvidence
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyError

/** Wat de keuring moet aantonen (F2.5). */
data class AttestExpectation(
    val aaguid: Aaguid,
    val keyClass: KeyClass,
    /** true = gemaakt met een token → UV=1 vereist; false = alleen aanraking (UP). */
    val requireUv: Boolean,
    val rpId: String,
)

sealed class AttestOutcome {
    /** [leafSha256] = SHA-256 (hex) van het leaf-certificaat, voor het rapport. */
    data class Ok(val leafSha256: String) : AttestOutcome()
    /** [stop] is één van de ATTEST_*-stops. */
    data class Failed(val stop: Stop) : AttestOutcome()
}

/**
 * Brug naar `attest/AttestationVerifier` (packed + x5c tot de gevendorde roots, leaf-AAGUID ==
 * authData-AAGUID == [AttestExpectation.aaguid], klasse, vlaggen UP/UV/BE/BS/AT, rpIdHash, ES256).
 * De app-laag levert de implementatie; flow/ kent alleen deze interface.
 */
fun interface AttestationJudge {
    fun judge(evidence: AttestationEvidence, expected: AttestExpectation): AttestOutcome
}

/** Omgevingscontrole voor de flows zonder event-machine (F4b, F5, F6, F7b). Lege lijst = in orde. */
fun interface EnvironmentProbe {
    fun violations(): List<Stop>

    companion object {
        val NONE = EnvironmentProbe { emptyList() }
    }
}

/** Niet-geheime melding voor de UI (bijv. "geen aanraking, probeer opnieuw"). */
data class Notice(val text: String, val pinRetriesLeft: Int? = null)

/** Interne afbreking met een stop; verlaat de flow-code nooit. */
internal class FlowStop(val stop: Stop) : Exception(stop.name) {
    override fun fillInStackTrace(): Throwable = this
}

internal object ErrorMap {
    /** Herstelbaar: niets veranderd, opnieuw proberen mag. */
    fun retriable(e: Throwable): Boolean = e is KeyError.UserActionTimeout || e is KeyError.Cancelled

    /** Generieke vertaling van een sleutelfout naar een stop. */
    fun stopFor(e: Throwable): Stop = when (e) {
        is FlowStop -> e.stop
        is KeyError.Disconnected -> Stop.KEY_REMOVED
        is KeyError.MultipleKeys -> Stop.MULTIPLE_KEYS
        is KeyError.PinBlocked -> Stop.PIN_BLOCKED
        is KeyError.PinAuthBlocked -> Stop.PIN_RETRIES_LOW
        is KeyError.UvBlocked -> Stop.UV_BLOCKED
        is KeyError.PinUvAuthTokenRequired -> Stop.INTERNAL_ERROR
        else -> Stop.INTERNAL_ERROR
    }

    /** Coroutine-annulering nooit opslokken. */
    fun rethrowIfCancellation(e: Throwable) {
        if (e is CancellationException) throw e
    }

    fun noticeFor(e: Throwable): Notice = when (e) {
        is KeyError.UserActionTimeout -> Notice("Geen aanraking binnen de tijd. Kies \"Opnieuw proberen\".")
        is KeyError.Cancelled -> Notice("Afgebroken. Kies \"Opnieuw proberen\".")
        is KeyError.UvInvalid -> Notice("Vinger niet herkend.")
        is KeyError.PinInvalid -> Notice("De PIN klopt niet.", e.retriesLeft)
        else -> Notice("Er ging iets mis.")
    }
}

/** Uitkomst van de flows zonder event-machine (F4, F5, F6, F7). Bevat nooit een geheim. */
sealed class FlowOutcome {
    /** Klaar; [report] null als de flow geen rapport maakt (oefenen). */
    data class Done(val report: nl.icthorse.horsesafe.report.Report?, val stop: Stop? = null, val pinRetries: Int? = null) : FlowOutcome()
    /** F6 open: vingerlijst en maximale naamlengte in bytes. */
    data class Ready(val fingers: List<nl.icthorse.horsesafe.yubikey.api.Enrollment>, val maxNameBytes: Int, val pinRetries: Int?) : FlowOutcome()
    /** De sleutel weigerde de PIN; er is een poging gebruikt. */
    data class PinRejected(val retriesLeft: Int?) : FlowOutcome()
    /** Syntaxcontrole vóór de poging faalde (lengte/alfabet); er is GEEN poging gebruikt. */
    data object SyntaxInvalid : FlowOutcome()
    /** Geblokkeerd vóór of tijdens de bewerking; na een blokkade gebeurt er niets meer op de sleutel. */
    data class Blocked(val stop: Stop) : FlowOutcome()
    /** Verzoek geweigerd zonder sleutelverkeer (bijv. ongeldige naam, maximum bereikt). */
    data class Refused(val reason: String) : FlowOutcome()
    /** F6: verwijderen van de laatste vinger vraagt een extra bevestiging. */
    data object NeedsConfirmLast : FlowOutcome()
    /** F6: testaanraking. */
    data class Touch(val ok: Boolean, val uvRetries: Int?) : FlowOutcome()
    /** Herstelbare fout (geen aanraking, afgebroken); niets veranderd. */
    data class Retriable(val notice: Notice) : FlowOutcome()
}

internal object PinPreflight {
    /** Syntax vóór een poging: 63 tekens uit het alfabet (F5.2: geen controle tegen een referentie). */
    fun syntaxOk(pin: nl.icthorse.horsesafe.pin.SecretBuffer): Boolean = nl.icthorse.horsesafe.pin.PinGenerator.isWellFormed(pin)

    /** Blokkade bij ≤ 3 pogingen (M8-banner). */
    fun retriesStop(r: Int?): Stop? = when {
        r == 0 -> Stop.PIN_BLOCKED
        r == null || r <= Limits.PIN_RETRIES_BLOCK_AT -> Stop.PIN_RETRIES_LOW
        else -> null
    }
}

/** Vertaalt fouten in een flow-stap naar een [FlowOutcome]; coroutine-annulering gaat door. */
internal suspend fun guarded(block: suspend () -> FlowOutcome): FlowOutcome = try {
    block()
} catch (e: Throwable) {
    ErrorMap.rethrowIfCancellation(e)
    when {
        e is FlowStop -> FlowOutcome.Blocked(e.stop)
        e is KeyError.PinInvalid -> FlowOutcome.PinRejected(e.retriesLeft)
        ErrorMap.retriable(e) -> FlowOutcome.Retriable(ErrorMap.noticeFor(e))
        else -> FlowOutcome.Blocked(ErrorMap.stopFor(e))
    }
}
