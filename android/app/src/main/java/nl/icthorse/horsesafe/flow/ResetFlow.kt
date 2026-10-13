package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyLink

/** Uitkomst van een stap in [ResetFlow]. Bevat nooit het volledige serienummer. */
sealed class ResetOutcome {
    /** Uitgelezen: dit wordt gewist. [serialLast4] = laatste 4 cijfers, om over te typen. */
    data class Ready(val facts: KeyFacts, val serialLast4: String) : ResetOutcome()
    /** Gewist en nagelezen: geen PIN en geen vingers meer. */
    data class Wiped(val facts: KeyFacts) : ResetOutcome()
    /** Herstelbaar (te laat na insteken, geen aanraking, los tijdens het wissen): opnieuw insteken. */
    data class Retry(val notice: Notice) : ResetOutcome()
    data class Blocked(val stop: Stop) : ResetOutcome()
}

/**
 * F8 Sleutel wissen (0.3.1, akkoord Christian 13-10-2026). Wist het FIDO-deel van één sleutel:
 *
 * 1. [inspect]: herkennen + serienummer via Management. Zonder serienummer geen wissen
 *    ([Stop.RESET_NO_SERIAL]): dan is niet te controleren dat straks dezelfde sleutel terugkomt.
 * 2. [confirm]: de gebruiker typt de laatste 4 cijfers over (de UI vraagt daarna 3 s ingedrukt houden).
 * 3. [wipe] op de OPNIEUW ingestoken sleutel (de YubiKey accepteert reset alleen kort na insteken):
 *    eerst serienummer en AAGUID vergelijken ([Stop.RESET_OTHER_KEY]), dan reset + aanraking, dan
 *    nalezen ([Stop.RESET_READBACK_FAILED] als er nog een PIN of vinger staat).
 *
 * Het volledige serienummer blijft in deze klasse en komt niet in de UI-staat of een rapport.
 */
class ResetFlow(private val inspector: InspectorOps) {
    private var serial: Int? = null
    private var aaguid: Aaguid? = null
    private var last4: String? = null
    private var confirmed = false

    suspend fun inspect(link: KeyLink): ResetOutcome = guardedReset {
        forget()
        val facts = inspector.inspect(link)
        if (facts.keyClass == KeyClass.UNKNOWN) return@guardedReset ResetOutcome.Blocked(Stop.AAGUID_NOT_ALLOWED)
        val s = link.readManagement()?.serial ?: return@guardedReset ResetOutcome.Blocked(Stop.RESET_NO_SERIAL)
        serial = s
        aaguid = facts.aaguid
        val l4 = lastDigits(s)
        last4 = l4
        ResetOutcome.Ready(facts, l4)
    }

    /** true als [typed] gelijk is aan de laatste 4 cijfers; pas dan mag [wipe]. */
    fun confirm(typed: String): Boolean {
        val ok = last4 != null && typed == last4
        confirmed = ok
        return ok
    }

    val isConfirmed: Boolean get() = confirmed

    suspend fun wipe(link: KeyLink): ResetOutcome = guardedReset {
        val expected = serial
        if (!confirmed || expected == null) return@guardedReset ResetOutcome.Blocked(Stop.INTERNAL_ERROR)
        // Snel: alleen Management, want het resetvenster na insteken is maar enkele seconden.
        val now = link.readManagement()?.serial
        if (now != expected) return@guardedReset ResetOutcome.Blocked(Stop.RESET_OTHER_KEY)
        link.ctap { reset.wipeFido() }
        val after = inspector.inspect(link)
        if (after.aaguid != aaguid) return@guardedReset ResetOutcome.Blocked(Stop.RESET_OTHER_KEY)
        if (after.option("clientPin") == true || after.option("bioEnroll") == true) {
            return@guardedReset ResetOutcome.Blocked(Stop.RESET_READBACK_FAILED)
        }
        confirmed = false
        ResetOutcome.Wiped(after)
    }

    /** Vergeet sleutel en bevestiging. */
    fun forget() {
        serial = null
        aaguid = null
        last4 = null
        confirmed = false
    }

    companion object {
        fun lastDigits(serial: Int): String = serial.toString().takeLast(4).padStart(4, '0')

        val NOTICE_TOO_LATE = Notice("Te laat: de sleutel accepteert wissen alleen vlak na het insteken. Haal hem eruit en steek hem meteen weer in (of houd hem opnieuw tegen de telefoon).")
        val NOTICE_NO_TOUCH = Notice("Niet aangeraakt binnen de tijd; er is niets gewist. Haal de sleutel eruit, steek hem weer in en raak hem aan zodra de app erom vraagt.")
        val NOTICE_LOST = Notice("De verbinding viel weg tijdens het wissen. Steek de sleutel opnieuw in; de app controleert daarna wat er nog op staat.")
        val NOTICE_DENIED = Notice("De sleutel weigerde het wissen. Haal hem eruit, steek hem weer in en raak hem aan.")
    }
}

private suspend fun guardedReset(block: suspend () -> ResetOutcome): ResetOutcome = try {
    block()
} catch (e: Throwable) {
    ErrorMap.rethrowIfCancellation(e)
    when (e) {
        is FlowStop -> ResetOutcome.Blocked(e.stop)
        is KeyError.ResetWindowPassed -> ResetOutcome.Retry(ResetFlow.NOTICE_TOO_LATE)
        is KeyError.UserActionTimeout, is KeyError.Cancelled -> ResetOutcome.Retry(ResetFlow.NOTICE_NO_TOUCH)
        is KeyError.Disconnected -> ResetOutcome.Retry(ResetFlow.NOTICE_LOST)
        is KeyError.OperationDenied -> ResetOutcome.Retry(ResetFlow.NOTICE_DENIED)
        is KeyError.MultipleKeys -> ResetOutcome.Blocked(Stop.MULTIPLE_KEYS)
        else -> ResetOutcome.Blocked(ErrorMap.stopFor(e))
    }
}
