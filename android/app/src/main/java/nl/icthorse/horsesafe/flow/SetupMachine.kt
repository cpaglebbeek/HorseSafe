package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.flow.StateFlow

/**
 * Toestandsmachine zonder UI voor inrichten (F2, F3) en hervatten (F2r/F3r). Een overgang kan alleen
 * als de vorige stap vers is teruggelezen; geen terugwaartse overgang; elke staat kan naar
 * [State.Stopped], en na een stop volgt geen schrijfactie meer.
 *
 * Volgorde per profiel: zie [Profile.attestTiming]; setMinPinLength(63) alleen na [State.ConfirmIrreversible];
 * alwaysUv alleen toggelen bij false.
 */
interface SetupMachine {
    val profile: Profile
    val mode: SetupMode
    val state: StateFlow<State>

    /** Verwerkt één event (suspend: kan CTAP-fases draaien) en geeft de nieuwe staat terug. */
    suspend fun handle(event: FlowEvent): State

    /** Wist alle PIN-buffers die de machine vasthoudt (ook in `onCleared`/`onStop`). Idempotent. */
    fun wipeSecrets()
}
