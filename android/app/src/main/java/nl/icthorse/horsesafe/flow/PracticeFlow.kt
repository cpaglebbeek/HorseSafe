package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.Permission

/**
 * F7 Oefenen.
 * - (a) [checkGroup]/[checkPaper]: per groep 7 tekens + controleteken, lokaal, zonder sleutel; er wordt
 *   niets opgeslagen.
 * - (b) [verifyOnKey]: optioneel één echte controle via `pinToken(pin, CM)` (kritiek 1: altijd met
 *   permissie, nooit 0x09 zonder permissie). Een juiste PIN zet de teller terug op 8; een foute kost een
 *   poging. Bij ≤ 3 pogingen geblokkeerd.
 */
class PracticeFlow(private val env: EnvironmentProbe = EnvironmentProbe.NONE) {

    /** Eén groep (7 tekens vanaf [offset]) tegen het getypte controleteken. */
    fun checkGroup(chars: CharArray, offset: Int, check: Char): Boolean = GroupCheck.verifyGroup(chars, offset, check)

    /** Hele PIN tegen 9 controletekens; 1-based nummers van de groepen die niet kloppen. */
    fun checkPaper(pin: SecretBuffer, checks: CharArray): List<Int> = GroupCheck.badGroups(pin, checks)

    /** (b) [pin] wordt altijd gewist. */
    suspend fun verifyOnKey(link: KeyLink, pin: SecretBuffer): FlowOutcome = try {
        guarded {
            env.violations().firstOrNull()?.let { return@guarded FlowOutcome.Blocked(it) }
            if (!PinPreflight.syntaxOk(pin)) return@guarded FlowOutcome.SyntaxInvalid
            val before = link.ctap { this.pin.pinRetries() }.count
            PinPreflight.retriesStop(before)?.let { return@guarded FlowOutcome.Blocked(it) }
            val after = link.ctap {
                this.pin.pinToken(pin, Permission.CM).use { }
                this.pin.pinRetries()
            }.count
            if (after != Limits.FULL_PIN_RETRIES) FlowOutcome.Blocked(Stop.PIN_READBACK_FAILED)
            else FlowOutcome.Done(null, null, after)
        }
    } finally {
        pin.wipe()
    }
}
