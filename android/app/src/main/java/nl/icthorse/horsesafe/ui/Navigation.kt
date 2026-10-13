package nl.icthorse.horsesafe.ui

import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Written

/** Schermen van deel 1. [code] is de vaste naam uit het bouwplan. */
enum class Screen(val code: String, val titel: String, val holdsSecret: Boolean = false) {
    M0_START("M0", "Start"),
    M1_CHECKLIST("M1", "Checklist"),
    M2_CONNECT("M2", "Sleutel aansluiten"),
    M3_JUDGEMENT("M3", "Oordeel"),
    M4_REVEAL("M4", "PIN tonen", holdsSecret = true),
    M5_COPY("M5", "Overschrijven", holdsSecret = true),
    M6_RETYPE("M6", "Overtypen", holdsSecret = true),
    M6B_IRREVERSIBLE("M6b", "Onomkeerbaar"),
    M7_FINGERS("M7", "Vingers"),
    M8_PIN_ENTRY("M8", "PIN invoeren", holdsSecret = true),
    M9_KEURING("M9", "Keuring"),
    M10_REPORT("M10", "Rapport"),
    M11_STOP("M11", "Stop"),
    M12_ABOUT("M12", "Over"),
    M13_RESET("M13", "Sleutel wissen"),
    BUSY("—", "Bezig"),
}

/** Wat de gebruiker in M0 kiest. */
enum class Purpose(val nl: String, val available: Boolean = true) {
    SETUP_NEW("Nieuwe sleutel inrichten"),
    SETUP_RESUME("Inrichting hervatten"),
    KEURING_ZONDER_PIN("Keuren zonder PIN"),
    KEURING_MET_PIN("Keuren met PIN"),
    PIN_CHANGE("PIN wijzigen"),
    FINGERS("Vingers beheren"),
    PRACTICE("Oefenen"),
    RESET("Sleutel wissen"),
}

/**
 * Pure afleiding van het scherm uit de staat van de [nl.icthorse.horsesafe.flow.SetupMachine] plus een
 * paar UI-keuzes. Los testbaar.
 *
 * @param copyStep gebruiker is van M4 naar M5 (overschrijven controleren) gegaan.
 * @param resumeEntryOpen gebruiker koos in M3 "PIN van papier invoeren" (hervatten).
 * @param minPending setMinPinLength(63) moet nog; dan wacht de machine in CountsOk op M6b.
 */
internal fun setupScreen(
    s: State,
    profile: Profile,
    busy: Boolean,
    copyStep: Boolean,
    resumeEntryOpen: Boolean,
    minPending: Boolean,
): Screen {
    if (s is State.Stopped) return Screen.M11_STOP
    if (s is State.ReportReady || s == State.Done) return Screen.M10_REPORT
    if (s == State.AlwaysUvOk && profile == Profile.BIO_MAIN) return Screen.M7_FINGERS
    if (busy) return Screen.BUSY
    return when (s) {
        State.Idle, is State.EnvOk -> Screen.M2_CONNECT
        is State.Detected, State.GateNewOk -> Screen.M3_JUDGEMENT
        is State.GateResumeOk -> if (resumeEntryOpen) Screen.M8_PIN_ENTRY else Screen.M3_JUDGEMENT
        State.PinGenerated -> if (copyStep) Screen.M5_COPY else Screen.M4_REVEAL
        State.PinShown -> Screen.M6_RETYPE
        is State.CountsOk -> if (minPending) Screen.M6B_IRREVERSIBLE else Screen.BUSY
        else -> Screen.BUSY
    }
}

/** Houdt de machine in deze staat een PIN in het geheugen? (dan wissen bij onStop, A-11) */
internal fun machineHoldsPin(s: State): Boolean = s.order in State.PinGenerated.order..State.FinalInspect.order

/** Stappenlijst voor het bezig-scherm, per profiel. */
internal data class Step(val label: String, val doneFromOrder: Int)

internal fun stepsFor(profile: Profile, pending: Set<Written>?): List<Step> = buildList {
    add(Step("Sleutel herkend en beoordeeld", State.GateNewOk.order))
    if (profile == Profile.RECOVERY_YK5) {
        add(Step("Echtheid gekeurd (attestation)", State.AttestOkBeforePin.order))
        add(Step("PIN op de sleutel", State.PinSet(0).order))
    } else {
        add(Step("PIN op de sleutel", State.PinSet(0).order))
        add(Step("Echtheid gekeurd (attestation)", State.AttestOkAfterPin.order))
    }
    add(Step("Sleutel is leeg (geteld)", State.CountsOk(0, 0).order))
    if (pending == null || Written.MIN_PIN_LENGTH_63 in pending) add(Step("Minimum PIN-lengte 63 vastgezet", State.MinLenSet.order))
    add(Step("alwaysUv aan", State.AlwaysUvOk.order))
    if (profile == Profile.RECOVERY_YK5) add(Step("U2F gecontroleerd", State.U2fChecked(false).order))
    if (profile == Profile.BIO_MAIN) add(Step("Vingers ingeschreven en getest", State.FingersOk(0).order))
    add(Step("Eindinspectie", State.FinalInspect.order))
    // ReportReady (order 17) direct vóór Done (18).
    add(Step("Rapport", State.Done.order - 1))
}
