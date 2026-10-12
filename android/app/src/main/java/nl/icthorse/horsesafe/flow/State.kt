package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.report.Report
import nl.icthorse.horsesafe.yubikey.api.KeyFacts

/** Wat al onomkeerbaar op de sleutel staat; getoond op M11 na een stop. */
enum class Written { PIN, MIN_PIN_LENGTH_63, ALWAYS_UV, FINGERPRINTS }

/**
 * Toestand van [SetupMachine]. Bevat NOOIT een geheim (alleen tellers en feiten), zodat hij veilig in
 * Compose-state mag. [order] dwingt "geen terugwaartse overgang" af: een overgang mag alleen naar een
 * hogere order, of naar [Stopped]. Optionele stappen per profiel (attest-moment, U2F, vingers) worden
 * overgeslagen, niet herhaald.
 */
sealed class State(val order: Int) {
    data object Idle : State(0)
    data class EnvOk(val warnings: List<CheckResult>) : State(1)
    data class Detected(val facts: KeyFacts, val checks: List<CheckResult>) : State(2)
    /** Nieuw-sleutelgate gehaald (clientPin/bioEnroll/forcePinChange false). */
    data object GateNewOk : State(3)
    /** Hervat-gate gehaald; [pending] = wat nog moet. PIN wordt daarna via M8 ingevoerd. */
    data class GateResumeOk(val pending: Set<Written>) : State(3)
    data object PinGenerated : State(4)
    data object PinShown : State(5)
    data object PinRetypedOk : State(6)
    /** Attestation vóór setPin (YK5, of Bio met alwaysUv=false). */
    data object AttestOkBeforePin : State(7)
    data class PinSet(val pinRetries: Int) : State(8)
    /** Attestation direct na setPin (Bio met alwaysUv=true), vóór het minimum. */
    data object AttestOkAfterPin : State(9)
    data class CountsOk(val residentCredentials: Int, val fingers: Int) : State(10)
    data object ConfirmIrreversible : State(11)
    data object MinLenSet : State(12)
    data object AlwaysUvOk : State(13)
    /** YK5: [u2fStillListed] true = oranje "afwijkend, vastgelegd" (kritiek 10), geen stop. */
    data class U2fChecked(val u2fStillListed: Boolean) : State(14)
    data class FingersOk(val count: Int) : State(15)
    data object FinalInspect : State(16)
    data class ReportReady(val report: Report) : State(17)
    /** PIN gewist; "Afsluiten" beëindigt het proces (A-12). */
    data object Done : State(18)
    data class Stopped(val stop: Stop, val written: Set<Written>, val fingers: Int) : State(Int.MAX_VALUE)
}
