package nl.icthorse.horsesafe.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import nl.icthorse.horsesafe.biometric.BioAvailability
import nl.icthorse.horsesafe.biometric.GateException
import nl.icthorse.horsesafe.net.DeviceKey
import nl.icthorse.horsesafe.pairing.DeviceInfo
import nl.icthorse.horsesafe.pairing.DeviceRecord
import nl.icthorse.horsesafe.pairing.LocalState
import nl.icthorse.horsesafe.pairing.PairingError
import nl.icthorse.horsesafe.pairing.PairingFlow
import nl.icthorse.horsesafe.pairing.PairingQr

/** Stap binnen "Telefoon koppelen"; [screen] is het schermnummer (M14-M19). */
enum class PairStep(val screen: Screen) {
    INTRO(Screen.M14_PAIR),
    WORKING(Screen.M14_PAIR),
    SCAN(Screen.M15_PAIR_SCAN),
    SAS(Screen.M16_PAIR_SAS),
    DONE(Screen.M17_PAIRED),
    BIO_BLOCKED(Screen.M18_BIO_REQUIRED),
    REPAIR(Screen.M19_REPAIR),
}

/** Wat de koppelschermen tonen. Bevat nooit een geheim (geen QR-geheim, geen sk_c, geen inhoud van de kopie). */
data class PairingUi(
    val step: PairStep = PairStep.INTRO,
    val bio: BioAvailability = BioAvailability.OK,
    val working: String? = null,
    val sas: String? = null,
    val label: String? = null,
    val active: Boolean = false,
    val keys: List<DeviceKey> = emptyList(),
    val message: String? = null,
    val error: String? = null,
    /** Er staat al een koppeling: eerst bevestigen dat die vervangen wordt. */
    val confirmReplace: Boolean = false,
    val trialFor: String? = null,
    val trialResult: String? = null,
)

/** Wat de koppel-UI van de app nodig heeft (in de app: `app/ServiceLocator`; in tests: nep). */
interface PairingServices {
    val flow: PairingFlow
    fun bioAvailability(): BioAvailability
    fun deviceInfo(): DeviceInfo
}

/**
 * Stuurt "Telefoon koppelen" aan (HARDWARE_KEYS §13.3 stap 2, 5, 6). Geen netwerk- of biometriecode hier:
 * dat zit in `pairing/`, `net/`, `keystore/` en `biometric/`. De omgevingsbewaking van de PIN-schermen
 * blokkeert koppelen niet (er is geen PIN in beeld); FLAG_SECURE geldt wel.
 */
class PairingViewModel(
    private val services: PairingServices,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {

    private val _ui = MutableStateFlow(PairingUi())
    val ui: StateFlow<PairingUi> = _ui.asStateFlow()

    private var job: Job? = null
    private var pollJob: Job? = null
    private var lastRejectedQr: String? = null

    /** M0 → koppelen: bestaande koppeling tonen, anders uitleg (of blokkade zonder sterke vinger). */
    fun open() {
        cancelJobs()
        val bio = services.bioAvailability()
        val rec = try {
            services.flow.current()
        } catch (e: RuntimeException) {
            null
        }
        when {
            rec != null -> {
                val active = rec.state == LocalState.ACTIVE
                _ui.value = fromRecord(rec, if (active) PairStep.DONE else PairStep.SAS, bio)
                job = viewModelScope.launch {
                    val valid = withContext(io) { services.flow.keysValid() }
                    if (!valid) {
                        _ui.value = PairingUi(step = PairStep.REPAIR, bio = services.bioAvailability())
                    } else if (active) {
                        refresh()
                    } else {
                        startPolling()
                    }
                }
            }
            bio != BioAvailability.OK -> _ui.value = PairingUi(step = PairStep.BIO_BLOCKED, bio = bio)
            else -> _ui.value = PairingUi(step = PairStep.INTRO, bio = bio)
        }
    }

    /** M18 "Opnieuw controleren". */
    fun recheck() {
        val bio = services.bioAvailability()
        _ui.update { if (bio == BioAvailability.OK) it.copy(step = PairStep.INTRO, bio = bio, error = null) else it.copy(bio = bio) }
    }

    /** "QR-code scannen" (camera-toestemming is dan al gegeven). */
    fun startScan() {
        val bio = services.bioAvailability()
        if (bio != BioAvailability.OK) {
            _ui.update { it.copy(step = PairStep.BIO_BLOCKED, bio = bio) }
            return
        }
        val existing = services.flow.current()
        if (existing != null && !_ui.value.confirmReplace) {
            _ui.update { it.copy(confirmReplace = true, step = PairStep.INTRO, error = null) }
            return
        }
        cancelJobs()
        lastRejectedQr = null
        _ui.update { it.copy(step = PairStep.SCAN, error = null, message = null) }
    }

    fun clearMessage() = _ui.update { it.copy(message = null) }

    fun cancelReplace() = _ui.update { it.copy(confirmReplace = false) }

    fun cameraDenied() = _ui.update {
        it.copy(step = PairStep.INTRO, error = "Zonder toegang tot de camera kan de app de QR-code niet lezen. Geef de toestemming en probeer opnieuw.")
    }

    /** Tekst uit de scanner. Alleen een geldige `hs1p:`-code start de koppeling. */
    fun onQr(text: String) {
        if (_ui.value.step != PairStep.SCAN) return
        val qr = PairingQr.parse(text)
        if (qr == null) {
            if (text != lastRejectedQr) {
                lastRejectedQr = text
                _ui.update { it.copy(message = "Dit is geen koppelcode van HorseSafe. Scan de QR-code op de laptop.") }
            }
            return
        }
        _ui.update { it.copy(step = PairStep.WORKING, working = "Sleutels maken…", message = null, error = null, confirmReplace = false) }
        val bio = services.bioAvailability()
        if (bio != BioAvailability.OK) {
            qr.wipe()
            _ui.update { it.copy(step = PairStep.BIO_BLOCKED, bio = bio, working = null) }
            return
        }
        job = viewModelScope.launch {
            try {
                val rec = withContext(io) { services.flow.claim(qr, services.deviceInfo()) }
                _ui.value = fromRecord(rec, PairStep.SAS, bio)
                startPolling()
            } catch (c: CancellationException) {
                qr.wipe()
                throw c
            } catch (t: Throwable) {
                qr.wipe()
                fail(t)
            }
        }
    }

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            try {
                val rec = withContext(io) { services.flow.awaitActive() }
                _ui.value = fromRecord(rec, PairStep.DONE, _ui.value.bio).copy(message = "Gekoppeld. De laptop heeft de code bevestigd.")
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                fail(t)
            }
        }
    }

    /** M17: status één keer verversen (sleutels, intrekking). */
    fun refresh() {
        job?.cancel()
        job = viewModelScope.launch {
            try {
                val rec = withContext(io) { services.flow.refresh(transientOk = true) }
                if (rec != null) _ui.update { fromRecord(rec, it.step, it.bio).copy(message = it.message, trialResult = it.trialResult) }
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                fail(t)
            }
        }
    }

    /** §13.3 stap 6: proef "Kopie openen" voor één sleutel. Toont alleen of de vorm klopt. */
    fun trial(key: DeviceKey) {
        if (job?.isActive == true) return
        _ui.update { it.copy(trialFor = key.keyId, trialResult = null, error = null, working = "Kopie ophalen…") }
        job = viewModelScope.launch {
            try {
                val r = withContext(io) { services.flow.trialOpen(key) }
                val parts = listOfNotNull(if (r.hasPh) "wachtwoord" else null, if (r.hasKh) "keyfile" else null).joinToString(" en ")
                _ui.update { it.copy(working = null, trialResult = "Kopie klopt: de telefoon kan de verzegelde kopie openen ($parts aanwezig). Er is niets getoond of bewaard.") }
            } catch (c: CancellationException) {
                throw c
            } catch (t: Throwable) {
                _ui.update { it.copy(working = null) }
                fail(t)
            }
        }
    }

    /** Afbreken of terug: lopende stap stoppen (een halve koppeling wist de flow zelf). */
    fun cancel() {
        cancelJobs()
        val bio = services.bioAvailability()
        val rec = services.flow.current()
        _ui.value = if (rec != null) fromRecord(rec, if (rec.state == LocalState.ACTIVE) PairStep.DONE else PairStep.SAS, bio)
        else PairingUi(step = if (bio == BioAvailability.OK) PairStep.INTRO else PairStep.BIO_BLOCKED, bio = bio)
        if (rec != null && rec.state == LocalState.PENDING) startPolling()
    }

    /**
     * M16 "Koppeling op deze telefoon afbreken": lokaal alles wissen (koppelbestand en sleutels). Op de
     * laptop blijft de koppeling open tot daar "Klopt niet" of annuleren wordt gekozen.
     */
    fun abandon() {
        cancelJobs()
        job = viewModelScope.launch {
            withContext(io) { services.flow.wipeLocal() }
            restart()
        }
    }

    /** M19 / na een fout: opnieuw beginnen. */
    fun restart() {
        cancelJobs()
        val bio = services.bioAvailability()
        _ui.value = PairingUi(step = if (bio == BioAvailability.OK) PairStep.INTRO else PairStep.BIO_BLOCKED, bio = bio)
    }

    /** Scherm verlaten (terug naar M0): alles stoppen; een openstaande koppeling blijft lokaal `pending`. */
    fun leave() {
        cancelJobs()
        _ui.value = PairingUi()
    }

    /** onStop van de activity: camera dicht (de scanner verdwijnt met de stap). */
    fun onStop() {
        if (_ui.value.step == PairStep.SCAN) _ui.update { it.copy(step = PairStep.INTRO) }
    }

    private fun cancelJobs() {
        job?.cancel()
        job = null
        pollJob?.cancel()
        pollJob = null
    }

    private fun fail(t: Throwable) {
        when (t) {
            PairingError.KeysInvalidated -> _ui.value = PairingUi(step = PairStep.REPAIR, bio = services.bioAvailability())
            PairingError.Revoked -> _ui.value = PairingUi(step = PairStep.INTRO, bio = services.bioAvailability(), error = errorText(t))
            else -> {
                val rec = try {
                    services.flow.current()
                } catch (e: RuntimeException) {
                    null
                }
                val step = when {
                    rec?.state == LocalState.ACTIVE -> PairStep.DONE
                    rec != null -> PairStep.SAS
                    else -> PairStep.INTRO
                }
                val base = if (rec != null) fromRecord(rec, step, _ui.value.bio) else PairingUi(step = step, bio = _ui.value.bio)
                _ui.value = base.copy(error = errorText(t))
            }
        }
    }

    private fun fromRecord(rec: DeviceRecord, step: PairStep, bio: BioAvailability) = PairingUi(
        step = step,
        bio = bio,
        sas = rec.sas,
        label = rec.label,
        active = rec.state == LocalState.ACTIVE,
        keys = rec.keys,
    )

    override fun onCleared() {
        cancelJobs()
        super.onCleared()
    }

    companion object {
        /** Nederlandse foutteksten; geen technische details of serverteksten. */
        fun errorText(t: Throwable): String = when (t) {
            is GateException -> when (t.kind) {
                GateException.Kind.CANCELLED -> "Afgebroken bij de vingerafdruk. Er is niets gekoppeld."
                GateException.Kind.LOCKOUT -> "Te veel mislukte pogingen met de vingerafdruk. Wacht even en probeer opnieuw. Een toestel-PIN telt hier niet."
                GateException.Kind.NOT_AVAILABLE -> "De vingerafdruksensor is nu niet beschikbaar."
                GateException.Kind.NOT_BIOMETRIC, GateException.Kind.FAILED -> "De vingerafdruk is niet gelukt. Er is niets gekoppeld."
            }
            is PairingError.Keystore -> "De beveiligde sleutelopslag van dit toestel weigerde (${t.why}). Koppelen kan op dit toestel niet."
            is PairingError.ChainShape -> "De sleutelattestatie van dit toestel past niet in het koppelcontract. Koppelen kan op dit toestel niet."
            is PairingError.SasMismatch -> "De server meldt een andere controlecode dan de telefoon berekent. De koppeling is afgebroken; probeer opnieuw met een nieuwe QR-code."
            is PairingError.DeviceUnknown -> deviceUnknownText(t)
            is PairingError.Revoked -> "Dit toestel is op de laptop verwijderd. Op de telefoon is alles gewist; koppel opnieuw als dat de bedoeling is."
            is PairingError.Timeout -> "De laptop heeft de code niet binnen 10 minuten bevestigd. Open dit scherm opnieuw om verder te wachten, of begin opnieuw."
            is PairingError.NotPaired -> "Er is geen koppeling op deze telefoon."
            is PairingError.Storage -> "De koppeling kon niet worden opgeslagen."
            is PairingError.Unseal -> "De kopie ging niet open (${t.code}). Ontgrendel op de laptop met wachtwoord en keyfile en controleer de koppeling."
            is PairingError.Api -> apiText(t)
            is PairingError.KeysInvalidated -> "De vingerafdrukken op dit toestel zijn gewijzigd; koppel opnieuw."
            else -> "Er ging iets mis. Er is niets gekoppeld."
        }

        /** 401/404: niets gewist; bij een afwijkende klok die als oorzaak noemen. */
        private fun deviceUnknownText(e: PairingError.DeviceUnknown): String {
            val skew = e.clockSkewSeconds
            if (skew != null) {
                val min = (kotlin.math.abs(skew) + 59) / 60
                val richting = if (skew > 0) "voor" else "achter"
                return "De klok van deze telefoon loopt ongeveer $min min $richting op de server; daardoor wordt het toestel niet herkend. " +
                    "Zet datum en tijd op \"automatisch\" en probeer opnieuw. Er is niets gewist."
            }
            return "De server herkent dit toestel nu niet (HTTP ${e.status}). Er is niets gewist. Probeer het later opnieuw; " +
                "is de koppeling op de laptop afgewezen, verlopen of verwijderd, breek haar dan hier af en koppel opnieuw."
        }

        private fun apiText(e: PairingError.Api): String = when {
            e.status == 0 && e.code == "network" -> "Geen verbinding met HorseSafe. Controleer internet (vliegtuigmodus uit) en probeer opnieuw."
            e.status == 0 -> "Onverwacht antwoord van de server. Er is niets gekoppeld."
            e.code == "pairing_not_found" -> "Deze QR-code is verlopen, al gebruikt of ingetrokken. Maak op de laptop een nieuwe."
            e.code == "pairing_mac_invalid" -> "De QR-code klopt niet bij deze koppeling. Scan de code opnieuw (na 3 fouten maak je een nieuwe)."
            e.code == "attestation_invalid" -> "De server keurt de sleutels van dit toestel af" + (e.reason?.let { " ($it)" } ?: "") + "."
            e.code == "attestation_status_unavailable" -> "De server kan de intrekkingslijst van Google nu niet controleren. Probeer het later opnieuw."
            e.code == "signature_invalid" -> "De handtekening van dit toestel werd niet aanvaard. Probeer opnieuw."
            e.code == "too_many_devices" -> "Er zijn al 5 toestellen gekoppeld. Verwijder eerst een toestel op de laptop."
            e.status == 429 -> "Te veel pogingen. Wacht tien minuten en probeer opnieuw."
            e.status == 401 -> "De server herkent dit toestel niet (meer)."
            else -> "De server weigerde (HTTP ${e.status}" + (e.code?.let { ", $it" } ?: "") + ")."
        }

        fun factory(services: PairingServices): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = PairingViewModel(services) as T
        }
    }
}
