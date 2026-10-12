package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.yubikey.api.KeyLink

/**
 * Invoer voor [SetupMachine.handle] vanuit UI en detectie. Een event met een [SecretBuffer] geeft
 * alleen een verwijzing door; de machine wist die buffer zelf na gebruik (de UI bewaart hem niet).
 */
sealed class FlowEvent {
    /** F0: uitkomst van `secure/EnvironmentGuard`; lege lijst = in orde. */
    data class EnvironmentChecked(val violations: List<Stop>) : FlowEvent()
    data class KeyConnected(val link: KeyLink) : FlowEvent()
    data object KeyRemoved : FlowEvent()
    data object MultipleKeys : FlowEvent()
    /** M3 afgevinkt. */
    data object ChecklistConfirmed : FlowEvent()
    /** M4 klaar: alle 9 groepen zijn getoond en overgeschreven. */
    data object RevealFinished : FlowEvent()
    /** M5: hertypte PIN (buffer B); de machine vergelijkt in constante tijd met A. */
    class PinRetyped(val retyped: SecretBuffer) : FlowEvent()
    /** M8: PIN van papier (hervatten, keuren met PIN, PIN wijzigen, oefenen). */
    class PinEntered(val pin: SecretBuffer) : FlowEvent()
    /** M6: vinkje + "Ik begrijp het, vastzetten". */
    data object IrreversibleConfirmed : FlowEvent()
    /** M7: één vinger inschrijven met deze naam (bv. `R-wijs`). */
    data class EnrollFinger(val name: String) : FlowEvent()
    /** M7: klaar met vingers. */
    data object FingersDone : FlowEvent()
    /**
     * "Opnieuw proberen" na een herstelbare fout in een automatische stap (geen aanraking binnen de tijd,
     * afgebroken aanraking). Toegevoegd in de flow-fase; voert de openstaande stap opnieuw uit.
     */
    data object Retry : FlowEvent()
    /** Activity/proces werd herbouwd (A-5). */
    data object Recreated : FlowEvent()
    /** Gebruiker breekt af. */
    data object Cancel : FlowEvent()
    /** M10 "Afsluiten". */
    data object Quit : FlowEvent()
}
