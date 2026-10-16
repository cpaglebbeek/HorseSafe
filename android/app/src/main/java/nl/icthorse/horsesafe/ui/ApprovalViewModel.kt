package nl.icthorse.horsesafe.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import nl.icthorse.horsesafe.approval.ApprovalCard
import nl.icthorse.horsesafe.approval.ApprovalError
import nl.icthorse.horsesafe.approval.ApprovalFlow
import nl.icthorse.horsesafe.approval.ApproveOutcome
import nl.icthorse.horsesafe.approval.CardTrust
import nl.icthorse.horsesafe.biometric.GateException
import nl.icthorse.horsesafe.net.ApprovalWire
import nl.icthorse.horsesafe.pairing.PairingError

/**
 * Wat de goedkeuringskaart (M20) toont. Geen geheimen: alleen browsernaam, kluis, IP, UA en tijd.
 * [result] = afsluitende melding na een beslissing; [resultOk] = goedgekeurd.
 */
data class ApprovalUi(
    val card: ApprovalCard? = null,
    val working: String? = null,
    val result: String? = null,
    val resultOk: Boolean = false,
    /** De app weigerde zelf (handtekening of koppelbewijs klopt niet). */
    val untrusted: Boolean = false,
    val error: String? = null,
)

/** Wat de goedkeuring van de app nodig heeft (in de app: `app/ServiceLocator`; in tests: nep). */
interface ApprovalServices {
    val approvals: ApprovalFlow
}

/**
 * Ontgrendelverzoeken van een vertrouwde browser (HARDWARE_KEYS §14.5, §14.9).
 *
 * Foreground-polling: zolang [setActive] true is (app zichtbaar, telefoon gekoppeld, geen PIN-scherm) loopt één
 * long-poll-lus (`status?wait=25`). Een nieuw verzoek wordt opgehaald, de handtekening wordt VÓÓR de vinger
 * gecontroleerd en de kaart verschijnt. Tijdens een open kaart staat de lus stil.
 */
class ApprovalViewModel(
    private val services: ApprovalServices,
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val retryMs: Long = RETRY_MS,
    private val idleMs: Long = IDLE_MS,
) : ViewModel() {

    private val _ui = MutableStateFlow(ApprovalUi())
    val ui: StateFlow<ApprovalUi> = _ui.asStateFlow()

    private var pollJob: Job? = null
    private var actionJob: Job? = null

    /** Verzoeken die al getoond of afgehandeld zijn (niet opnieuw tonen terwijl de server nog bijwerkt). */
    private val seen = LinkedHashSet<String>()

    /** Polling aan (voorgrond, geschikt scherm) of uit. */
    fun setActive(active: Boolean) {
        if (active) {
            if (pollJob?.isActive == true) return
            pollJob = viewModelScope.launch { loop() }
        } else {
            pollJob?.cancel()
            pollJob = null
        }
    }

    private suspend fun loop() {
        val flow = services.approvals
        while (currentCoroutineContext().isActive) {
            if (_ui.value.card != null || _ui.value.result != null || actionJob?.isActive == true) {
                delay(SHORT_MS)
                continue
            }
            if (!withContext(io) { flow.paired() }) {
                delay(idleMs)
                continue
            }
            val pending = try {
                withContext(io) { flow.poll() }
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                // Tijdelijk (netwerk, 5xx, 401/404) of intrekking: de koppelschermen tonen de details.
                delay(if (t is PairingError.Api) retryMs else idleMs)
                continue
            }
            val next = pending.firstOrNull { it.approvalId !in seen }
            if (next == null) {
                delay(SHORT_MS) // ook als een server zonder long-polling meteen antwoordt: geen strakke lus
                continue
            }
            remember(next.approvalId)
            try {
                val card = withContext(io) { flow.load(next) }
                _ui.value = ApprovalUi(card = card, untrusted = card.trust == CardTrust.SIG_INVALID)
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                if (t !is ApprovalError.Gone) _ui.value = ApprovalUi(error = errorText(t), result = errorText(t))
            }
        }
    }

    private fun remember(id: String) {
        seen += id
        while (seen.size > MAX_SEEN) seen.remove(seen.first())
    }

    /** "Goedkeuren (vinger)". */
    fun approve() {
        val card = _ui.value.card ?: return
        if (!card.canApprove || actionJob?.isActive == true) return
        _ui.update { it.copy(working = "Wachten op je vinger…", error = null) }
        actionJob = viewModelScope.launch {
            try {
                when (val out = withContext(io) { services.approvals.approve(card) }) {
                    ApproveOutcome.Approved ->
                        _ui.value = ApprovalUi(result = "Goedgekeurd. De kluis gaat open in de browser \"${card.browserLabel}\".", resultOk = true)
                    is ApproveOutcome.Rejected -> _ui.value = ApprovalUi(result = rejectedText(out.reason), untrusted = true)
                }
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                _ui.update { it.copy(working = null, error = errorText(t)) }
                if (t is ApprovalError.Gone || t is PairingError.KeysInvalidated || t is PairingError.Revoked) {
                    _ui.value = ApprovalUi(result = errorText(t))
                }
            }
        }
    }

    /** "Weigeren" ([revoke] = false) of "Weigeren en browser intrekken" ([revoke] = true). */
    fun deny(revoke: Boolean) {
        val card = _ui.value.card ?: return
        if (actionJob?.isActive == true) return
        _ui.update { it.copy(working = "Weigeren…", error = null) }
        actionJob = viewModelScope.launch {
            try {
                withContext(io) { services.approvals.deny(card, revoke) }
                _ui.value = ApprovalUi(
                    result = if (revoke) {
                        "Geweigerd. De browser \"${card.browserLabel}\" is niet meer vertrouwd en de sessie is ingetrokken."
                    } else {
                        "Geweigerd. De sessie in de browser is ingetrokken."
                    },
                )
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                if (t is ApprovalError.Gone) {
                    _ui.value = ApprovalUi(result = errorText(t))
                } else {
                    _ui.update { it.copy(working = null, error = errorText(t)) }
                }
            }
        }
    }

    /** Kaart of melding sluiten (zonder beslissing; het verzoek verloopt dan op de server). */
    fun dismiss() {
        if (actionJob?.isActive == true) return
        _ui.value = ApprovalUi()
    }

    override fun onCleared() {
        pollJob?.cancel()
        actionJob?.cancel()
        super.onCleared()
    }

    companion object {
        private const val RETRY_MS = 5_000L
        private const val IDLE_MS = 30_000L
        private const val SHORT_MS = 1_000L
        private const val MAX_SEEN = 100

        const val UNTRUSTED = "Verzoek niet vertrouwd — mogelijk gemanipuleerd"

        fun rejectedText(reason: String): String = when (reason) {
            ApprovalWire.REASON_PROOF_INVALID ->
                "$UNTRUSTED. Het koppelbewijs van deze browser klopt niet bij je kluis. Het verzoek is geweigerd; de kluis bleef dicht."
            ApprovalWire.REASON_KH_MISSING ->
                "Deze kluis heeft geen keyfile. Ontgrendelen via een vertrouwde browser kan alleen bij een kluis met keyfile. Het verzoek is geweigerd."
            else -> "Het verzoek is geweigerd."
        }

        /** Nederlandse foutteksten; geen technische details of serverteksten. */
        fun errorText(t: Throwable): String = when (t) {
            is GateException -> when (t.kind) {
                GateException.Kind.CANCELLED -> "Afgebroken bij de vingerafdruk. Er is niets beslist; je kunt alsnog goedkeuren of weigeren."
                GateException.Kind.LOCKOUT -> "Te veel mislukte pogingen met de vingerafdruk. Wacht even. Een toestel-PIN telt hier niet."
                GateException.Kind.NOT_AVAILABLE -> "De vingerafdruksensor is nu niet beschikbaar."
                GateException.Kind.NOT_BIOMETRIC, GateException.Kind.FAILED -> "De vingerafdruk is niet gelukt. Er is niets beslist."
            }
            is ApprovalError.Gone -> "Dit verzoek is al afgehandeld of verlopen."
            is ApprovalError.Unseal -> "De kopie op deze telefoon ging niet open (${t.code}). Is de kluis in KeePassXC gewijzigd? Ontgrendel op de laptop met wachtwoord en keyfile."
            is ApprovalError.BadBrowserKey -> "$UNTRUSTED: de tijdelijke sleutel van de browser is onbruikbaar. Weiger dit verzoek."
            is PairingError.KeysInvalidated -> "De vingerafdrukken op dit toestel zijn gewijzigd; koppel opnieuw."
            is PairingError.Revoked -> "Dit toestel is op de laptop verwijderd. Op de telefoon is alles gewist."
            is PairingError.DeviceUnknown -> "De server herkent dit toestel nu niet (HTTP ${t.status}). Controleer datum en tijd; er is niets gewist."
            is PairingError.NotPaired -> "Deze telefoon heeft geen (actieve) koppeling voor deze kluis."
            is PairingError.Keystore -> "De beveiligde sleutelopslag weigerde (${t.why})."
            is PairingError.Api -> when {
                t.status == 0 && t.code == "network" -> "Geen verbinding met HorseSafe. Probeer opnieuw."
                t.status == 0 -> "Onverwacht antwoord van de server. Er is niets beslist."
                else -> "De server weigerde (HTTP ${t.status}" + (t.code?.let { ", $it" } ?: "") + ")."
            }
            is IllegalStateException, is IllegalArgumentException -> "$UNTRUSTED. Er is niets goedgekeurd."
            else -> "Er ging iets mis. Er is niets goedgekeurd."
        }

        fun factory(services: ApprovalServices): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = ApprovalViewModel(services) as T
        }
    }
}
