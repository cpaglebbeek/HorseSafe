package nl.icthorse.horsesafe.ui

import android.content.ContentResolver
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import nl.icthorse.horsesafe.flow.ChangePinFlow
import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.DefaultSetupMachine
import nl.icthorse.horsesafe.flow.EnvironmentProbe
import nl.icthorse.horsesafe.flow.FingerFlow
import nl.icthorse.horsesafe.flow.FlowEvent
import nl.icthorse.horsesafe.flow.FlowOutcome
import nl.icthorse.horsesafe.flow.Gates
import nl.icthorse.horsesafe.flow.KeuringFlow
import nl.icthorse.horsesafe.flow.Notice
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.ResetFlow
import nl.icthorse.horsesafe.flow.ResetOutcome
import nl.icthorse.horsesafe.flow.SetupMachine
import nl.icthorse.horsesafe.flow.SetupMode
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Written
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.report.Report
import nl.icthorse.horsesafe.report.ReportCompare
import nl.icthorse.horsesafe.report.ReportComparison
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.report.ReportSchemaException
import nl.icthorse.horsesafe.report.SafReportIo
import nl.icthorse.horsesafe.secure.EnvReport
import nl.icthorse.horsesafe.secure.SecretRegistry
import nl.icthorse.horsesafe.yubikey.api.EnrollProgress
import nl.icthorse.horsesafe.yubikey.api.Enrollment
import nl.icthorse.horsesafe.yubikey.api.KeyDiscovery
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.KeyLinkEvent
import nl.icthorse.horsesafe.yubikey.api.TemplateId

/** Aanwezigheid van een sleutel volgens de detectie. */
enum class KeyPresence { NONE, CONNECTED, MULTIPLE }

/** Toestand van de hold-to-reveal op M4. [pressed] = groep die nu ingedrukt is (0-based). */
data class RevealUi(val seen: Set<Int> = emptySet(), val pressed: Int? = null)

/** Stap in de flows zonder event-machine (F4, F5, F6, F7b). */
enum class MaintStep { CONNECT, NEW_PIN_REVEAL, NEW_PIN_COPY, NEW_PIN_RETYPE, PIN_ENTRY, FINGERS, BUSY, RESULT }

enum class CodeTarget { SEAL, PAPER }

/** F8 Sleutel wissen: stappen op M13. */
enum class ResetStep { CONNECT, CONFIRM, REPLUG, WIPING, DONE }

/**
 * M13. [serialLast4] = laatste 4 cijfers van het serienummer (staat ook op de sleutel; geen geheim),
 * [typed] = wat de gebruiker overtypte. Het volledige serienummer staat alleen in [ResetFlow].
 */
data class ResetUi(
    val step: ResetStep = ResetStep.CONNECT,
    val serialLast4: String? = null,
    val typed: String = "",
    val typedOk: Boolean = false,
    val typedWrong: Boolean = false,
    val notice: String? = null,
    val attempts: Int = 0,
)

/**
 * Alles wat de Compose-schermen tonen. Bevat NOOIT een geheim: geen PIN, geen controletekens, geen
 * token (A-11). [toString] is dus veilig; een test controleert dat met een kanarie-PIN.
 */
data class UiState(
    val screen: Screen = Screen.M0_START,
    val purpose: Purpose? = null,
    val profile: Profile? = null,
    /** M0: kies eerst een rol voor dit doel. */
    val pickProfileFor: Purpose? = null,
    val busy: Boolean = false,
    val env: EnvReport = EnvReport.CLEAN,
    /** false bij focusverlies, pauze of schermopname: de PIN verbergt zich (A-4). */
    val windowVisible: Boolean = true,
    val key: KeyPresence = KeyPresence.NONE,
    val machine: State? = null,
    val maint: MaintStep? = null,
    val facts: KeyFacts? = null,
    val checks: List<CheckResult> = emptyList(),
    val pending: Set<Written>? = null,
    val notice: Notice? = null,
    val fingers: List<Enrollment> = emptyList(),
    val enrollProgress: EnrollProgress? = null,
    val maxNameBytes: Int = 15,
    val confirmLast: TemplateId? = null,
    val renameFor: TemplateId? = null,
    val checklist: Set<Int> = emptySet(),
    val reveal: RevealUi = RevealUi(),
    val copyConfirmed: Boolean = false,
    val entry: EntryUi? = null,
    /** PIN-pogingen voor de banner in M8 (flows zonder machine). */
    val pinRetries: Int? = null,
    val irreversibleTicked: Boolean = false,
    val report: Report? = null,
    val comparison: ReportComparison? = null,
    /** Rapport aan het eind van inrichten, PIN wijzigen of vingers beheren: daarna alleen Afsluiten. */
    val finalReport: Boolean = false,
    val reportSaved: Boolean = false,
    val archive: List<Report> = emptyList(),
    val archiveRejected: Int = 0,
    /** Korte melding (export gelukt, import geweigerd, ...). */
    val message: String? = null,
    /** Stop die de UI of een flow zonder machine vaststelde. */
    val localStop: Stop? = null,
    /** Er is in dit proces een PIN gemaakt of ingevoerd die de sleutel zag: dan alleen nog "Afsluiten" (A-12). */
    val secretsTouched: Boolean = false,
    /** Signaal aan de activity: proces beëindigen (ProcessEnd). */
    val quit: Boolean = false,
    /** Oefenen op de sleutel (F7b): uitkomst. */
    val practiceKeyResult: String? = null,
    /** Ingevoerde codes (noodsleutel): zak en papierlocatie. Geen geheim. */
    val sealCode: String = "",
    val paperLocationCode: String = "",
    val codeTarget: CodeTarget? = null,
    /** F8 Sleutel wissen (M13); null buiten die flow. */
    val reset: ResetUi? = null,
)

/**
 * Stuurt de [SetupMachine] (F2, F3, hervatten) en de flows zonder machine (F4, F5, F6, F7) aan en leidt
 * het scherm af. PIN's staan alleen in [PinEntryController]-buffers (hier) of in machine/flow; de
 * Compose-state ([ui]) bevat alleen tellers en statussen.
 */
class HorseSafeViewModel(
    private val services: AppServices,
    private val work: CoroutineDispatcher = Dispatchers.Default,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) : ViewModel() {

    private val _ui = MutableStateFlow(UiState())
    val ui: StateFlow<UiState> = _ui.asStateFlow()

    private var machine: SetupMachine? = null
    private var machineJobs: List<Job> = emptyList()
    private val events = Channel<FlowEvent>(Channel.UNLIMITED)
    private var current: Job? = null

    private var discovery: KeyDiscovery? = null
    private var discoveryJob: Job? = null
    private var lastLink: KeyLink? = null

    private var entry: PinEntryController? = null
    private var copyStep = false
    private var resumeEntryOpen = false
    private var stoppedWhileHoldingPin = false
    private var started = false

    // flows zonder machine
    private val envProbe = EnvironmentProbe { _ui.value.env.violations }
    private var keuring: KeuringFlow? = null
    private var changePin: ChangePinFlow? = null
    private var changePinSubmitted = false
    private var fingerFlow: FingerFlow? = null
    private var maintLink: KeyLink? = null
    private var practicePin: SecretBuffer? = null
    private var maintJob: Job? = null
    private var maintInterrupted = false
    private var resetFlow: ResetFlow? = null

    private val wiper = SecretRegistry.register { wipeAllSecrets() }

    init {
        viewModelScope.launch {
            for (e in events) {
                val m = machine ?: continue
                _ui.update { it.copy(busy = true) }
                val job = launch(work) {
                    try {
                        m.handle(e)
                    } catch (c: CancellationException) {
                        throw c
                    } catch (t: Throwable) {
                        _ui.update { it.copy(localStop = Stop.INTERNAL_ERROR) }
                    }
                }
                current = job
                job.join()
                current = null
                _ui.update { it.copy(busy = false) }
                recompute()
            }
        }
        refreshArchive()
    }

    // ================================================================== M0

    fun choose(purpose: Purpose) {
        if (!purpose.available) {
            _ui.update { it.copy(message = "Deze functie komt in een volgende stap van deel 1.") }
            return
        }
        when (purpose) {
            Purpose.PRACTICE -> {
                _ui.update { it.copy(purpose = purpose, profile = null, message = null, practiceKeyResult = null) }
                openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
            }
            Purpose.FINGERS -> start(purpose, Profile.BIO_MAIN)
            Purpose.RESET -> startReset()
            else -> _ui.update { it.copy(pickProfileFor = purpose, message = null) }
        }
    }

    /** Direct starten met een bekend doel en profiel. */
    fun start(purpose: Purpose, profile: Profile) {
        _ui.update { it.copy(pickProfileFor = purpose) }
        pickProfile(profile)
    }

    fun pickProfile(profile: Profile?) {
        val purpose = _ui.value.pickProfileFor ?: return
        if (profile == null) {
            _ui.update { it.copy(pickProfileFor = null) }
            return
        }
        _ui.update { it.copy(purpose = purpose, profile = profile, pickProfileFor = null, checklist = emptySet(), message = null) }
        when (purpose) {
            Purpose.KEURING_ZONDER_PIN -> {
                _ui.update { it.copy(screen = Screen.M2_CONNECT, maint = MaintStep.CONNECT) }
                startDiscovery()
            }
            else -> _ui.update { it.copy(screen = Screen.M1_CHECKLIST) }
        }
    }

    fun openAbout() = _ui.update { it.copy(screen = Screen.M12_ABOUT, message = null) }

    fun openReports() {
        refreshArchive()
        _ui.update { it.copy(screen = Screen.M10_REPORT, report = null, comparison = null, finalReport = false, message = null) }
    }

    /** Terug naar M0; alleen als er in dit proces nog geen geheim was (anders alleen Afsluiten). */
    fun backToStart() {
        val s = _ui.value
        if (s.secretsTouched) return
        if (s.busy) return
        wipeAllSecrets()
        disposeMachine()
        disposeMaint()
        stopDiscovery()
        _ui.value = UiState(env = s.env, windowVisible = s.windowVisible, archive = s.archive, archiveRejected = s.archiveRejected)
    }

    fun clearMessage() = _ui.update { it.copy(message = null) }

    // ================================================================== M1

    fun toggleChecklist(item: Int) = _ui.update {
        it.copy(checklist = if (item in it.checklist) it.checklist - item else it.checklist + item)
    }

    /** M1 afgevinkt: machine of flow starten; daarna M2. */
    fun checklistDone() {
        val s = _ui.value
        val profile = s.profile ?: return
        if (s.checklist.size < Texts.checklist.size) return
        when (s.purpose) {
            Purpose.SETUP_NEW, Purpose.SETUP_RESUME -> {
                val mode = if (s.purpose == Purpose.SETUP_RESUME) SetupMode.RESUME else SetupMode.NEW
                startMachine(profile, mode)
                send(FlowEvent.EnvironmentChecked(s.env.violations))
                startDiscovery()
                recompute()
            }
            Purpose.KEURING_MET_PIN, Purpose.PIN_CHANGE, Purpose.FINGERS -> {
                _ui.update { it.copy(screen = Screen.M2_CONNECT, maint = MaintStep.CONNECT) }
                startDiscovery()
            }
            else -> Unit
        }
    }

    // ================================================================== SetupMachine (F2, F3, hervatten)

    private fun startMachine(profile: Profile, mode: SetupMode) {
        disposeMachine()
        val m = services.createSetupMachine(profile, mode)
        machine = m
        val jobs = mutableListOf<Job>()
        jobs += viewModelScope.launch { m.state.collect { st -> onMachineState(st) } }
        (m as? DefaultSetupMachine)?.let { d ->
            jobs += viewModelScope.launch { d.notice.collect { n -> _ui.update { it.copy(notice = n) } } }
            jobs += viewModelScope.launch { d.fingers.collect { f -> _ui.update { it.copy(fingers = f) } } }
            jobs += viewModelScope.launch { d.enrollProgress.collect { p -> _ui.update { it.copy(enrollProgress = p) } } }
        }
        machineJobs = jobs
    }

    private fun disposeMachine() {
        machineJobs.forEach { it.cancel() }
        machineJobs = emptyList()
        machine?.wipeSecrets()
        machine = null
        lastLink = null
        copyStep = false
        resumeEntryOpen = false
    }

    private fun onMachineState(st: State) {
        _ui.update { u ->
            var n = u.copy(machine = st)
            when (st) {
                is State.Detected -> n = n.copy(facts = st.facts, checks = st.checks)
                is State.GateResumeOk -> n = n.copy(pending = st.pending)
                State.GateNewOk -> {
                    val f = n.facts ?: (machine as? DefaultSetupMachine)?.facts
                    val p = n.profile
                    if (f != null && p != null) n = n.copy(facts = f, pending = Gates.pendingFromFacts(f, p))
                }
                is State.ReportReady -> if (u.report == null) n = withReport(n, st.report)
                else -> Unit
            }
            if (st.order >= State.PinGenerated.order && st !is State.Stopped) n = n.copy(secretsTouched = true)
            if (st is State.Stopped && st.written.isNotEmpty()) n = n.copy(secretsTouched = true)
            n
        }
        // Het inrichtingsrapport is de basis voor de eerste keuring: direct bewaren, niet pas bij Afsluiten.
        if (st is State.ReportReady) autoSaveReport()
        recompute()
    }

    /** Bewaart het rapport meteen (zonder codes); [saveReportOnce] vervangt het later met de codes. */
    private var autoSavedCreatedAt: String? = null

    private fun autoSaveReport() {
        val r = _ui.value.report ?: return
        if (_ui.value.reportSaved || autoSavedCreatedAt == r.createdAt) return
        try {
            services.reports.save(r)
            autoSavedCreatedAt = r.createdAt
        } catch (e: Exception) {
            _ui.update { it.copy(message = "Rapport kon niet automatisch worden bewaard; gebruik Exporteren.") }
        }
        refreshArchive()
    }

    private fun withReport(u: UiState, raw: Report): UiState {
        if (raw.kind == ReportKind.SETUP || raw.kind == ReportKind.RESUME) {
            // Inrichting: nieuwe basis, geen vergelijking met (meestal) een andere sleutel van dit profiel.
            val basis = ReportCompare.asNewBasis(raw)
            return u.copy(report = basis, comparison = null, finalReport = true)
        }
        val previous = previousFor(raw)
        val compared = ReportCompare.apply(raw, previous)
        return u.copy(report = compared, comparison = ReportCompare.compare(previous, compared), finalReport = true)
    }

    private fun previousFor(r: Report): Report? = try {
        services.reports.baselineFor(r.profile, services.serialKeyId, before = r.createdAt)
    } catch (e: Exception) {
        null
    }

    /** M3 "Verder": nieuw → PIN maken (checklist is al afgevinkt in M1); hervatten → M8. */
    fun judgementContinue() {
        when (_ui.value.machine) {
            State.GateNewOk -> send(FlowEvent.ChecklistConfirmed)
            is State.GateResumeOk -> {
                resumeEntryOpen = true
                recompute()
            }
            else -> Unit
        }
    }

    // ================================================================== M4 / M5

    fun revealPress(group: Int) {
        if (!revealAllowed() || group !in 0 until GroupCheck.GROUPS) return
        _ui.update { it.copy(reveal = RevealUi(seen = it.reveal.seen + group, pressed = group)) }
    }

    fun revealRelease() = _ui.update { it.copy(reveal = it.reveal.copy(pressed = null)) }

    fun revealAllowed(u: UiState = _ui.value): Boolean =
        u.windowVisible && !u.env.blocksSecrets && !u.busy &&
            (u.machine == State.PinGenerated || u.maint == MaintStep.NEW_PIN_REVEAL)

    /**
     * Tekent groep [group] direct uit de CharArray van machine of flow (nooit als String, A-7):
     * [drawChars] krijgt (array, start, aantal, deel) voor 4 + 3 tekens en het controleteken.
     * Doet niets als tonen niet mag of de groep niet ingedrukt is.
     */
    fun drawGroup(group: Int, drawChars: (chars: CharArray, start: Int, count: Int, part: Int) -> Unit) {
        val u = _ui.value
        if (!revealAllowed(u) || u.reveal.pressed != group) return
        val draw: (SecretBuffer) -> Unit = { pin ->
            if (pin.length == SecretBuffer.PIN_LENGTH) {
                pin.useChars { a ->
                    val off = group * GroupCheck.GROUP_SIZE
                    drawChars(a, off, 4, 0)
                    drawChars(a, off + 4, 3, 1)
                }
                val check = CharArray(1)
                try {
                    check[0] = GroupCheck.checkChar(pin, group)
                    drawChars(check, 0, 1, 2)
                } finally {
                    check.fill('\u0000')
                }
            }
        }
        val d = machine as? DefaultSetupMachine
        if (d != null) d.revealPin(draw) else changePin?.revealNewPin(draw)
    }

    fun toCopyStep() {
        if (_ui.value.reveal.seen.size < GroupCheck.GROUPS) return
        _ui.update { it.copy(reveal = it.reveal.copy(pressed = null)) }
        if (machine != null) {
            copyStep = true
            recompute()
        } else if (_ui.value.maint == MaintStep.NEW_PIN_REVEAL) {
            _ui.update { it.copy(maint = MaintStep.NEW_PIN_COPY, screen = Screen.M5_COPY) }
        }
    }

    fun backToReveal() {
        if (machine != null) {
            copyStep = false
            recompute()
        } else if (_ui.value.maint == MaintStep.NEW_PIN_COPY) {
            _ui.update { it.copy(maint = MaintStep.NEW_PIN_REVEAL, screen = Screen.M4_REVEAL) }
        }
    }

    fun setCopyConfirmed(v: Boolean) = _ui.update { it.copy(copyConfirmed = v) }

    fun copyDone() {
        if (!_ui.value.copyConfirmed) return
        if (machine != null) {
            send(FlowEvent.RevealFinished)
        } else if (_ui.value.maint == MaintStep.NEW_PIN_COPY) {
            val cp = changePin ?: return
            _ui.update { it.copy(maint = MaintStep.NEW_PIN_RETYPE) }
            openEntry(EntryMode.RETYPE, Screen.M6_RETYPE) { g, typed -> cp.retypedGroupMatches(g, typed) }
        }
    }

    // ================================================================== M6 / M8 toetsenblok

    fun key(c: Char) {
        val e = entry ?: return
        val u = _ui.value
        if (u.env.blocksSecrets || !u.windowVisible || u.busy) return
        val ui = e.key(c)
        _ui.update { it.copy(entry = ui) }
    }

    fun deleteKey() {
        val e = entry ?: return
        _ui.update { it.copy(entry = e.delete()) }
    }

    /** M6 klaar (9 groene groepen) of M8 klaar (9 kloppende groepen). */
    fun entrySubmit() {
        val e = entry ?: return
        if (!e.ui.complete) return
        val u = _ui.value
        if (u.busy) return
        if (u.env.blocksSecrets) return
        if (machine != null) {
            when {
                e.mode == EntryMode.RETYPE && u.machine == State.PinShown -> {
                    val b = e.take() ?: return
                    entry = null
                    send(FlowEvent.PinRetyped(b))
                }
                e.mode == EntryMode.PAPER && u.machine is State.GateResumeOk -> {
                    if (pinRetriesBlocked(u)) return
                    val b = e.take() ?: return
                    entry = null
                    send(FlowEvent.PinEntered(b))
                }
            }
            return
        }
        submitMaintEntry(e, u)
    }

    /** Pogingen volgens de laatste melding, de flow of de detectie; ≤ 3 = geblokkeerd (M8). */
    fun pinRetries(u: UiState = _ui.value): Int? = u.notice?.pinRetriesLeft ?: u.pinRetries ?: u.facts?.pinRetries

    fun pinRetriesBlocked(u: UiState = _ui.value): Boolean {
        if (u.purpose == Purpose.PRACTICE) return false
        val r = pinRetries(u) ?: return true
        return r <= 3
    }

    private fun openEntry(mode: EntryMode, screen: Screen, matcher: ((Int, CharArray) -> Boolean)? = null) {
        entry?.wipe()
        val c = PinEntryController(mode, matcher)
        entry = c
        _ui.update { it.copy(entry = c.ui, screen = screen) }
    }

    // ================================================================== M6b / M7 / bezig (machine)

    fun setIrreversibleTicked(v: Boolean) = _ui.update { it.copy(irreversibleTicked = v) }

    fun confirmIrreversible() {
        if (!_ui.value.irreversibleTicked) return
        send(FlowEvent.IrreversibleConfirmed)
    }

    fun enrollFinger(name: String) {
        if (machine != null) send(FlowEvent.EnrollFinger(name)) else fingerAdd(name)
    }

    fun fingersDone() {
        if (machine != null) send(FlowEvent.FingersDone) else fingersClose()
    }

    fun retry() = send(FlowEvent.Retry)

    /** Afbreken: lopende sleutelactie annuleren; M11 toont daarna wat er op de sleutel staat. */
    fun cancel() {
        current?.cancel()
        if (machine != null) {
            send(FlowEvent.Cancel)
            return
        }
        maintJob?.cancel()
        val u = _ui.value
        if (u.secretsTouched) {
            wipeAllSecrets()
            stopDiscovery()
            _ui.update { it.copy(localStop = Stop.CANCELLED, busy = false, screen = Screen.M11_STOP) }
        } else {
            _ui.update { it.copy(busy = false) }
            backToStart()
        }
    }

    // ================================================================== flows zonder machine (F4, F5, F6, F7b)

    private fun keuringFlow(): KeuringFlow = keuring ?: services.keuringFlow(envProbe).also { keuring = it }

    private fun disposeMaint() {
        maintJob?.cancel()
        maintJob = null
        changePin?.wipeSecrets()
        changePin = null
        changePinSubmitted = false
        fingerFlow?.wipeSecrets()
        fingerFlow = null
        practicePin?.wipe()
        practicePin = null
        maintLink = null
        resetFlow?.forget()
        resetFlow = null
    }

    private fun maintHoldsSecret(): Boolean =
        practicePin != null || fingerFlow != null || (changePin != null && _ui.value.maint in setOf(
            MaintStep.NEW_PIN_REVEAL, MaintStep.NEW_PIN_COPY, MaintStep.NEW_PIN_RETYPE, MaintStep.PIN_ENTRY, MaintStep.BUSY,
        ))

    /** Draait een flow-stap buiten de main thread; [stayOn] = scherm tijdens het wachten (null = bezig-scherm). */
    private fun runMaint(stayOn: Screen? = null, block: suspend () -> FlowOutcome, then: (FlowOutcome) -> Unit) {
        if (_ui.value.busy) return
        _ui.update { it.copy(busy = true, screen = stayOn ?: Screen.BUSY, message = null) }
        maintJob = viewModelScope.launch {
            val out = try {
                withContext(work) { block() }
            } catch (c: CancellationException) {
                _ui.update { it.copy(busy = false) }
                throw c
            } catch (e: KeyError) {
                FlowOutcome.Blocked(if (e is KeyError.Disconnected) Stop.KEY_REMOVED else Stop.INTERNAL_ERROR)
            } catch (e: Throwable) {
                // Ook Errors hier afvangen: een uncaught exception komt anders via de platform-pre-handler
                // met bericht en stacktrace in logcat -b crash (zie CrashGuard).
                FlowOutcome.Blocked(Stop.INTERNAL_ERROR)
            }
            _ui.update { it.copy(busy = false, enrollProgress = null) }
            then(out)
        }
    }

    private fun onMaintConnected(link: KeyLink) {
        val u = _ui.value
        val profile = u.profile
        maintLink = link
        when (u.purpose) {
            Purpose.KEURING_ZONDER_PIN -> if (profile != null) runMaint(block = {
                keuringFlow().withoutPin(link, profile, latest(profile))
            }) { out -> onKeuringOutcome(out, withPin = false) }
            Purpose.KEURING_MET_PIN, Purpose.FINGERS -> runMaint(block = {
                val f = services.inspector.inspect(link)
                _ui.update { it.copy(facts = f, pinRetries = f.pinRetries) }
                val roleStop = if (u.purpose == Purpose.FINGERS) services.fingerFlow(envProbe).roleStop(f) else null
                if (roleStop != null) FlowOutcome.Blocked(roleStop) else FlowOutcome.Done(null, null, f.pinRetries)
            }) { out ->
                if (out is FlowOutcome.Blocked) toLocalStop(out.stop)
                else {
                    _ui.update { it.copy(maint = MaintStep.PIN_ENTRY) }
                    openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
                }
            }
            Purpose.PIN_CHANGE -> if (profile != null) {
                val cp = services.changePinFlow(profile, envProbe).also { changePin = it }
                runMaint(block = {
                    val r = cp.begin(link)
                    if (r is FlowOutcome.Done) {
                        try {
                            _ui.update { it.copy(facts = services.inspector.inspect(link)) }
                        } catch (e: KeyError) {
                            // feiten alleen voor de weergave
                        }
                    }
                    r
                }) { out ->
                    when (out) {
                        is FlowOutcome.Done -> {
                            if (cp.generateNewPin()) {
                                _ui.update {
                                    it.copy(
                                        maint = MaintStep.NEW_PIN_REVEAL, screen = Screen.M4_REVEAL, secretsTouched = true,
                                        reveal = RevealUi(), copyConfirmed = false, pinRetries = out.pinRetries,
                                    )
                                }
                            } else {
                                toLocalStop(envProbe.violations().firstOrNull() ?: Stop.INTERNAL_ERROR)
                            }
                        }
                        is FlowOutcome.Blocked -> toLocalStop(out.stop)
                        is FlowOutcome.Retriable -> backToConnect(out.notice.text)
                        else -> toLocalStop(Stop.INTERNAL_ERROR)
                    }
                }
            }
            Purpose.PRACTICE -> {
                val p = practicePin ?: return
                practicePin = null
                runMaint(block = { services.practiceFlow(envProbe).verifyOnKey(link, p) }) { out ->
                    val msg = when (out) {
                        is FlowOutcome.Done -> "De PIN klopt. De teller staat weer op ${out.pinRetries ?: 8}."
                        is FlowOutcome.PinRejected -> "De PIN klopt NIET. Nog ${out.retriesLeft ?: "?"} pogingen."
                        is FlowOutcome.SyntaxInvalid -> "De PIN is niet compleet; er is geen poging gebruikt."
                        is FlowOutcome.Blocked -> out.stop.tekst + " " + out.stop.advies
                        is FlowOutcome.Retriable -> out.notice.text
                        else -> "Controle niet gelukt."
                    }
                    // F7b is één echte controle (A-12): daarna geen nieuwe invoer, alleen Afsluiten.
                    wipeAllSecrets()
                    stopDiscovery()
                    _ui.update { it.copy(practiceKeyResult = msg, maint = MaintStep.RESULT, screen = Screen.M8_PIN_ENTRY, entry = null) }
                }
            }
            else -> Unit
        }
    }

    /** Vergelijkingsbasis voor een keuring: van vóór nu, eigen app-sleutel eerst. */
    private fun latest(profile: Profile): Report? = try {
        services.reports.baselineFor(profile, services.serialKeyId)
    } catch (e: Exception) {
        null
    }

    private fun backToConnect(msg: String) {
        _ui.update { it.copy(maint = MaintStep.CONNECT, screen = Screen.M2_CONNECT, message = msg) }
    }

    private fun toLocalStop(stop: Stop) {
        wipeAllSecrets()
        _ui.update { it.copy(localStop = stop, screen = Screen.M11_STOP, maint = MaintStep.RESULT, busy = false) }
    }

    private fun onKeuringOutcome(out: FlowOutcome, withPin: Boolean) {
        when (out) {
            is FlowOutcome.Done -> {
                val r = out.report
                if (r == null) {
                    toLocalStop(Stop.INTERNAL_ERROR)
                    return
                }
                val prev = latest(r.profile)
                try {
                    services.reports.save(r)
                } catch (e: Exception) {
                    _ui.update { it.copy(message = "Rapport kon niet worden bewaard.") }
                }
                refreshArchive()
                _ui.update {
                    it.copy(
                        report = r, comparison = ReportCompare.compare(prev?.takeIf { p -> p.createdAt != r.createdAt }, r),
                        reportSaved = true, maint = MaintStep.RESULT, screen = Screen.M9_KEURING,
                    )
                }
            }
            is FlowOutcome.PinRejected -> pinRejected(out.retriesLeft)
            FlowOutcome.SyntaxInvalid -> syntaxInvalid()
            is FlowOutcome.Blocked -> toLocalStop(out.stop)
            is FlowOutcome.Retriable -> if (withPin) {
                _ui.update { it.copy(maint = MaintStep.PIN_ENTRY, message = out.notice.text) }
                openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
            } else backToConnect(out.notice.text)
            else -> toLocalStop(Stop.INTERNAL_ERROR)
        }
    }

    private fun pinRejected(left: Int?) {
        _ui.update { it.copy(pinRetries = left, maint = MaintStep.PIN_ENTRY, message = "De PIN klopt niet. Nog ${left ?: "?"} pogingen. Controleer het papier met de controletekens.") }
        if (left == 0) toLocalStop(Stop.PIN_BLOCKED) else openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
    }

    private fun syntaxInvalid() {
        _ui.update { it.copy(maint = MaintStep.PIN_ENTRY, message = "De PIN is niet compleet of bevat een ongeldig teken; er is geen poging gebruikt.") }
        openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
    }

    private fun submitMaintEntry(e: PinEntryController, u: UiState) {
        val profile = u.profile
        when (u.purpose) {
            Purpose.PRACTICE -> Unit // afgerond: zie practiceAgain / practiceOnKey
            Purpose.PIN_CHANGE -> {
                val cp = changePin ?: return
                if (e.mode == EntryMode.RETYPE && u.maint == MaintStep.NEW_PIN_RETYPE) {
                    val b = e.take() ?: return
                    entry = null
                    if (cp.confirmRetyped(b)) {
                        _ui.update { it.copy(maint = MaintStep.PIN_ENTRY, message = "De nieuwe PIN klopt. Typ nu de HUIDIGE PIN van het oude papier.") }
                        openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
                    } else {
                        _ui.update { it.copy(message = "De hertypte PIN wijkt af. Controleer de groepen.") }
                        openEntry(EntryMode.RETYPE, Screen.M6_RETYPE) { g, t -> cp.retypedGroupMatches(g, t) }
                    }
                } else if (e.mode == EntryMode.PAPER && u.maint == MaintStep.PIN_ENTRY) {
                    if (pinRetriesBlocked(u)) return
                    val b = e.take() ?: return
                    entry = null
                    changePinSubmitted = true
                    runMaint(block = { cp.submit(b) }) { out ->
                        when (out) {
                            is FlowOutcome.Done -> finishWithReport(out.report)
                            is FlowOutcome.PinRejected -> pinRejected(out.retriesLeft)
                            FlowOutcome.SyntaxInvalid -> syntaxInvalid()
                            is FlowOutcome.Blocked -> toLocalStop(out.stop)
                            is FlowOutcome.Retriable -> {
                                _ui.update { it.copy(message = out.notice.text) }
                                openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
                            }
                            else -> toLocalStop(Stop.INTERNAL_ERROR)
                        }
                    }
                }
            }
            Purpose.KEURING_MET_PIN -> {
                val link = maintLink ?: return
                if (profile == null || pinRetriesBlocked(u)) return
                val b = e.take() ?: return
                entry = null
                _ui.update { it.copy(secretsTouched = true) }
                runMaint(block = { keuringFlow().withPin(link, profile, b, latest(profile)) }) { out -> onKeuringOutcome(out, withPin = true) }
            }
            Purpose.FINGERS -> {
                val link = maintLink ?: return
                if (pinRetriesBlocked(u)) return
                val b = e.take() ?: return
                entry = null
                _ui.update { it.copy(secretsTouched = true) }
                val ff = services.fingerFlow(envProbe).also { fingerFlow = it }
                runMaint(block = { ff.open(link, b) }) { out ->
                    when (out) {
                        is FlowOutcome.Ready -> _ui.update {
                            it.copy(maint = MaintStep.FINGERS, screen = Screen.M7_FINGERS, fingers = out.fingers, maxNameBytes = out.maxNameBytes)
                        }
                        is FlowOutcome.PinRejected -> { fingerFlow = null; pinRejected(out.retriesLeft) }
                        FlowOutcome.SyntaxInvalid -> { fingerFlow = null; syntaxInvalid() }
                        is FlowOutcome.Blocked -> toLocalStop(out.stop)
                        is FlowOutcome.Retriable -> {
                            fingerFlow = null
                            _ui.update { it.copy(message = out.notice.text) }
                            openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
                        }
                        else -> toLocalStop(Stop.INTERNAL_ERROR)
                    }
                }
            }
            else -> Unit
        }
    }

    /** F7a opnieuw. */
    fun practiceAgain() {
        if (_ui.value.practiceKeyResult != null) return // na F7b alleen Afsluiten
        _ui.update { it.copy(practiceKeyResult = null, maint = null) }
        openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
    }

    /** F7b: één echte controle op de sleutel met de net gecontroleerde PIN (kost een poging bij een fout). */
    fun practiceOnKey() {
        val e = entry ?: return
        val u = _ui.value
        if (u.purpose != Purpose.PRACTICE || !e.ui.complete || u.env.blocksSecrets || u.practiceKeyResult != null) return
        val b = e.take() ?: return
        entry = null
        practicePin?.wipe()
        practicePin = b
        _ui.update { it.copy(maint = MaintStep.CONNECT, screen = Screen.M2_CONNECT, secretsTouched = true, entry = null) }
        startDiscovery()
    }

    // ---- F6 vingers beheren

    private fun fingerAction(block: suspend (FingerFlow) -> FlowOutcome) {
        val ff = fingerFlow ?: return
        runMaint(stayOn = Screen.M7_FINGERS, block = { block(ff) }) { out ->
            _ui.update { it.copy(fingers = ff.current, confirmLast = null, renameFor = null) }
            when (out) {
                is FlowOutcome.Touch -> _ui.update {
                    it.copy(message = if (out.ok) "Testaanraking geslaagd (vingerpogingen: ${out.uvRetries ?: "?"})." else "Vinger niet herkend (nog ${out.uvRetries ?: "?"} pogingen).")
                }
                is FlowOutcome.Ready -> _ui.update { it.copy(fingers = out.fingers) }
                is FlowOutcome.Refused -> _ui.update { it.copy(message = out.reason) }
                is FlowOutcome.Retriable -> _ui.update { it.copy(message = out.notice.text) }
                is FlowOutcome.Blocked -> toLocalStop(out.stop)
                else -> Unit
            }
        }
    }

    private fun fingerAdd(name: String) {
        val ff = fingerFlow ?: return
        fingerAction { ff.add(name) { p -> _ui.update { it.copy(enrollProgress = p) } } }
    }

    fun fingerRename(id: TemplateId, name: String) = fingerAction { it.rename(id, name) }

    fun fingerAskRename(id: TemplateId?) = _ui.update { it.copy(renameFor = id) }

    fun fingerRemove(id: TemplateId) {
        val ff = fingerFlow ?: return
        val confirm = _ui.value.confirmLast == id
        runMaint(stayOn = Screen.M7_FINGERS, block = { ff.remove(id, confirmLast = confirm) }) { out ->
            _ui.update { it.copy(fingers = ff.current) }
            when (out) {
                FlowOutcome.NeedsConfirmLast -> _ui.update {
                    it.copy(confirmLast = id, message = "Dit is de laatste vinger. Zonder vinger val je terug op de PIN van 63 tekens. Tik nogmaals op Verwijderen om te bevestigen.")
                }
                is FlowOutcome.Touch -> _ui.update { it.copy(confirmLast = null, message = if (out.ok) "Verwijderd; testaanraking geslaagd." else "Verwijderd; testaanraking mislukt.") }
                is FlowOutcome.Ready -> _ui.update { it.copy(confirmLast = null, fingers = out.fingers, message = "Verwijderd.") }
                is FlowOutcome.Refused -> _ui.update { it.copy(message = out.reason) }
                is FlowOutcome.Retriable -> _ui.update { it.copy(message = out.notice.text) }
                is FlowOutcome.Blocked -> toLocalStop(out.stop)
                else -> Unit
            }
        }
    }

    fun fingerTouch() = fingerAction { it.testTouch() }

    private fun fingersClose() {
        val ff = fingerFlow ?: return
        runMaint(block = { FlowOutcome.Done(ff.close()) }) { out ->
            fingerFlow = null
            finishWithReport((out as? FlowOutcome.Done)?.report)
        }
    }

    /** Einde van F5/F6: rapport tonen (M10) en daarna alleen Afsluiten. */
    private fun finishWithReport(report: Report?) {
        wipeAllSecrets()
        stopDiscovery()
        if (report == null) {
            toLocalStop(Stop.INTERNAL_ERROR)
            return
        }
        _ui.update { withReport(it, report).copy(maint = MaintStep.RESULT, screen = Screen.M10_REPORT, secretsTouched = true) }
        autoSaveReport()
    }

    // ================================================================== M10 / M11

    fun quit() {
        val s = _ui.value
        if (machine != null && s.machine is State.ReportReady) {
            saveReportOnce()
            send(FlowEvent.Quit)
        } else {
            if (s.report != null && s.finalReport) saveReportOnce()
            wipeAllSecrets()
            _ui.update { it.copy(quit = true) }
        }
    }

    fun openCodeEntry(target: CodeTarget?) = _ui.update { it.copy(codeTarget = target) }

    /** Codes voor zak en papierlocatie (alleen bij een noodsleutel); tekens uit het PIN-alfabet. */
    fun codeKey(c: Char) = _ui.update { u ->
        if (u.reportSaved) return@update u
        when (u.codeTarget) {
            CodeTarget.SEAL -> if (u.sealCode.length < MAX_CODE) u.copy(sealCode = u.sealCode + c) else u
            CodeTarget.PAPER -> if (u.paperLocationCode.length < MAX_CODE) u.copy(paperLocationCode = u.paperLocationCode + c) else u
            null -> u
        }
    }

    fun codeDelete() = _ui.update { u ->
        when (u.codeTarget) {
            CodeTarget.SEAL -> u.copy(sealCode = u.sealCode.dropLast(1))
            CodeTarget.PAPER -> u.copy(paperLocationCode = u.paperLocationCode.dropLast(1))
            null -> u
        }
    }

    /** Bewaart het actuele rapport één keer in de app-privéopslag (met de codes). */
    fun saveReportOnce() {
        val u = _ui.value
        val r = u.report ?: return
        if (u.reportSaved) return
        val final = if (r.profile == Profile.BIO_MAIN) r
        else r.copy(sealCode = u.sealCode.ifEmpty { null }, paperLocationCode = u.paperLocationCode.ifEmpty { null })
        try {
            services.reports.save(final, replace = autoSavedCreatedAt == r.createdAt)
            _ui.update { it.copy(report = final, reportSaved = true, codeTarget = null, message = "Rapport bewaard in de app.") }
        } catch (e: Exception) {
            _ui.update { it.copy(message = "Rapport kon niet worden bewaard.") }
        }
        refreshArchive()
    }

    fun export(resolver: ContentResolver, uri: Uri) {
        saveReportOnce()
        val r = _ui.value.report ?: return
        viewModelScope.launch {
            val msg = try {
                withContext(io) { SafReportIo(resolver, services.reports).export(uri, r) }
                "Rapport geëxporteerd."
            } catch (e: Exception) {
                "Exporteren is mislukt."
            }
            _ui.update { it.copy(message = msg) }
        }
    }

    fun import(resolver: ContentResolver, uri: Uri) {
        viewModelScope.launch {
            val msg = try {
                val res = withContext(io) { SafReportIo(resolver, services.reports).import(uri) }
                if (res.alreadyPresent) "Dit rapport stond er al." else "Rapport geïmporteerd (${res.report.createdAt})."
            } catch (e: ReportSchemaException) {
                "Geweigerd: het bestand voldoet niet aan het rapportschema."
            } catch (e: Exception) {
                "Importeren is mislukt."
            }
            refreshArchive()
            _ui.update { it.copy(message = msg) }
        }
    }

    /** M10-archief → M9: een bewaard rapport bekijken met de vergelijking met het rapport ervoor. */
    fun openArchived(r: Report) {
        _ui.update { it.copy(screen = Screen.M9_KEURING, report = r, comparison = ReportCompare.compare(previousFor(r), r), reportSaved = true, finalReport = false) }
    }

    fun refreshArchive() {
        try {
            val c = services.reports.loadAll()
            _ui.update { it.copy(archive = c.reports.reversed(), archiveRejected = c.rejected) }
        } catch (e: Exception) {
            _ui.update { it.copy(archive = emptyList()) }
        }
    }

    // ================================================================== omgeving, venster, levenscyclus

    fun onEnvironment(report: EnvReport) {
        val before = _ui.value.env
        _ui.update { it.copy(env = report) }
        val st = _ui.value.machine
        if (report.violations.isNotEmpty() && report.violations != before.violations && machine != null &&
            (st == State.PinGenerated || st == State.PinShown || st is State.GateResumeOk)
        ) {
            send(FlowEvent.EnvironmentChecked(report.violations))
        }
        if (report.blocksSecrets) wipeEntry()
        recompute()
    }

    /** Focusverlies, pauze of schermopname: de PIN verbergt zich (A-4). */
    fun setWindowVisible(visible: Boolean) {
        _ui.update { it.copy(windowVisible = visible, reveal = if (visible) it.reveal else it.reveal.copy(pressed = null)) }
    }

    /**
     * A-3: het systeem meldde een schermafbeelding (API 34+). FLAG_SECURE maakt die zwart; de app meldt
     * het en sluit de ingedrukte PIN-groep tot de volgende aanraking.
     */
    fun onScreenCaptured() {
        _ui.update {
            it.copy(
                reveal = it.reveal.copy(pressed = null),
                message = "Er is een schermafbeelding gemaakt. Die blijft zwart door de beveiliging van dit scherm.",
            )
        }
    }

    fun onStart() {
        started = true
        val u = _ui.value
        if (machine != null || u.maint == MaintStep.CONNECT || u.maint == MaintStep.PIN_ENTRY || u.maint == MaintStep.FINGERS ||
            (u.purpose == Purpose.RESET && u.reset?.step != ResetStep.DONE)
        ) startDiscovery()
        if (stoppedWhileHoldingPin) {
            stoppedWhileHoldingPin = false
            send(FlowEvent.Recreated)
        }
        if (maintInterrupted) {
            maintInterrupted = false
            val stop = if (u.purpose == Purpose.PIN_CHANGE && !changePinSubmitted) Stop.RESTART_BEFORE_PIN else Stop.CANCELLED
            toLocalStop(stop)
        } else if (entry == null && (u.screen == Screen.M8_PIN_ENTRY || u.screen == Screen.M6_RETYPE) && machine == null &&
            u.practiceKeyResult == null
        ) {
            // invoer werd bij onStop gewist: opnieuw beginnen
            val cp = changePin
            if (u.screen == Screen.M6_RETYPE && cp != null) openEntry(EntryMode.RETYPE, Screen.M6_RETYPE) { g, t -> cp.retypedGroupMatches(g, t) }
            else openEntry(EntryMode.PAPER, Screen.M8_PIN_ENTRY)
        }
        recompute()
    }

    /** A-11: PIN-buffers wissen bij onStop; bij terugkeer stopt de lopende bewerking. */
    fun onStop() {
        started = false
        val st = _ui.value.machine
        if (st != null && machineHoldsPin(st)) {
            stoppedWhileHoldingPin = true
            machine?.wipeSecrets()
        }
        if (machine == null && maintHoldsSecret()) {
            maintInterrupted = true
            maintJob?.cancel()
            changePin?.wipeSecrets()
            fingerFlow?.wipeSecrets()
            practicePin?.wipe()
            practicePin = null
        }
        wipeEntry()
        _ui.update { it.copy(reveal = it.reveal.copy(pressed = null)) }
        stopDiscovery()
    }

    private fun wipeEntry() {
        val e = entry ?: return
        e.wipe()
        entry = null
        _ui.update { it.copy(entry = null) }
    }

    private fun wipeAllSecrets() {
        entry?.wipe()
        entry = null
        _ui.update { it.copy(entry = null) }
        machine?.wipeSecrets()
        changePin?.wipeSecrets()
        fingerFlow?.wipeSecrets()
        practicePin?.wipe()
        practicePin = null
    }

    // ================================================================== F8 Sleutel wissen (M13)

    private fun startReset() {
        disposeMaint()
        resetFlow = services.resetFlow()
        _ui.update {
            it.copy(purpose = Purpose.RESET, profile = null, maint = null, screen = Screen.M13_RESET, reset = ResetUi(), facts = null, message = null)
        }
        startDiscovery()
    }

    /** Vanaf M11 (stop bij een al ingerichte sleutel): terug naar start en meteen wissen. */
    fun wipeFromStop() {
        val u = _ui.value
        if (u.secretsTouched || u.busy) return
        val stop = (u.machine as? State.Stopped)?.stop ?: u.localStop ?: return
        if (stop !in Stop.WIPE_OFFERED) return
        backToStart()
        choose(Purpose.RESET)
    }

    private fun onResetKeyConnected(link: KeyLink) {
        val u = _ui.value
        val r = u.reset ?: return
        if (u.busy) return
        when (r.step) {
            ResetStep.CONNECT -> {
                maintLink = link
                runReset({ it.inspect(link) })
            }
            ResetStep.REPLUG -> if (link !== maintLink) {
                maintLink = link
                _ui.update { it.copy(reset = r.copy(step = ResetStep.WIPING, notice = null, attempts = r.attempts + 1)) }
                runReset({ it.wipe(link) })
            }
            else -> Unit
        }
    }

    private fun runReset(block: suspend (ResetFlow) -> ResetOutcome) {
        val f = resetFlow ?: return
        _ui.update { it.copy(busy = true, message = null) }
        maintJob = viewModelScope.launch {
            val out = try {
                withContext(work) { block(f) }
            } catch (c: CancellationException) {
                _ui.update { it.copy(busy = false) }
                throw c
            } catch (e: Throwable) {
                ResetOutcome.Blocked(Stop.INTERNAL_ERROR)
            }
            _ui.update { it.copy(busy = false) }
            onResetOutcome(out)
        }
    }

    private fun onResetOutcome(out: ResetOutcome) {
        val f = resetFlow
        when (out) {
            is ResetOutcome.Ready -> _ui.update {
                it.copy(facts = out.facts, reset = (it.reset ?: ResetUi()).copy(step = ResetStep.CONFIRM, serialLast4 = out.serialLast4, notice = null))
            }
            is ResetOutcome.Wiped -> {
                f?.forget()
                _ui.update { it.copy(facts = out.facts, reset = (it.reset ?: ResetUi()).copy(step = ResetStep.DONE, notice = null)) }
                stopDiscovery()
            }
            is ResetOutcome.Retry -> _ui.update {
                val step = if (f?.isConfirmed == true) ResetStep.REPLUG else ResetStep.CONNECT
                it.copy(reset = (it.reset ?: ResetUi()).copy(step = step, notice = out.notice.text))
            }
            is ResetOutcome.Blocked -> {
                f?.forget()
                toLocalStop(out.stop)
            }
        }
    }

    fun resetDigit(c: Char) {
        if (c !in '0'..'9') return
        val r = _ui.value.reset ?: return
        if (r.step != ResetStep.CONFIRM || r.typedOk || r.typed.length >= 4) return
        val typed = r.typed + c
        if (typed.length < 4) {
            _ui.update { it.copy(reset = r.copy(typed = typed, typedWrong = false)) }
            return
        }
        val ok = resetFlow?.confirm(typed) == true
        _ui.update { it.copy(reset = r.copy(typed = if (ok) typed else "", typedOk = ok, typedWrong = !ok)) }
    }

    fun resetDeleteDigit() {
        val r = _ui.value.reset ?: return
        if (r.step != ResetStep.CONFIRM || r.typedOk) return
        _ui.update { it.copy(reset = r.copy(typed = r.typed.dropLast(1), typedWrong = false)) }
    }

    /** M13: knop 3 s ingedrukt gehouden (de UI meet de tijd). Daarna: opnieuw insteken. */
    fun resetHoldComplete() {
        val u = _ui.value
        val r = u.reset ?: return
        if (r.step != ResetStep.CONFIRM || !r.typedOk || u.busy || u.env.blocksSecrets) return
        if (resetFlow?.isConfirmed != true) return
        _ui.update { it.copy(reset = r.copy(step = ResetStep.REPLUG, notice = null)) }
    }

    /** M13 na wissen: meteen inrichten met dit profiel. */
    fun setupAfterReset(profile: Profile) {
        if (_ui.value.reset?.step != ResetStep.DONE) return
        backToStart()
        start(Purpose.SETUP_NEW, profile)
    }

    // ================================================================== sleuteldetectie

    private fun startDiscovery() {
        if (!started) return
        val d = discovery ?: services.createDiscovery().also { discovery = it }
        val p = _ui.value.purpose
        val allowNfc = p == Purpose.KEURING_ZONDER_PIN || p == Purpose.RESET
        try {
            d.start(allowNfc)
        } catch (e: Exception) {
            _ui.update { it.copy(message = "Sleuteldetectie kon niet starten.") }
            return
        }
        if (discoveryJob == null) {
            discoveryJob = viewModelScope.launch { d.events.collect { ev -> onKeyEvent(ev) } }
        }
    }

    private fun stopDiscovery() {
        discoveryJob?.cancel()
        discoveryJob = null
        try {
            discovery?.stop()
        } catch (e: Exception) {
            // al gestopt
        }
        _ui.update { it.copy(key = KeyPresence.NONE) }
    }

    private fun onKeyEvent(ev: KeyLinkEvent) {
        val u = _ui.value
        when (ev) {
            KeyLinkEvent.None -> _ui.update { it.copy(key = KeyPresence.NONE) }
            is KeyLinkEvent.Connected -> {
                _ui.update { it.copy(key = KeyPresence.CONNECTED) }
                if (u.purpose == Purpose.RESET && machine == null) {
                    onResetKeyConnected(ev.link)
                } else if (machine != null) {
                    if (ev.link !== lastLink) {
                        lastLink = ev.link
                        send(FlowEvent.KeyConnected(ev.link))
                    }
                } else if (u.maint == MaintStep.CONNECT && !u.busy) {
                    onMaintConnected(ev.link)
                } else if (maintLink != null && ev.link !== maintLink && u.maint != MaintStep.RESULT) {
                    // andere of opnieuw ingestoken sleutel midden in een bewerking
                    toLocalStop(Stop.KEY_SWAPPED)
                }
            }
            KeyLinkEvent.Multiple -> {
                _ui.update { it.copy(key = KeyPresence.MULTIPLE) }
                if (machine != null) send(FlowEvent.MultipleKeys)
                else if (u.purpose == Purpose.RESET) {
                    if (u.reset?.step != ResetStep.DONE) {
                        maintJob?.cancel()
                        toLocalStop(Stop.MULTIPLE_KEYS)
                    }
                } else if (maintLink != null && u.maint != MaintStep.RESULT) toLocalStop(Stop.MULTIPLE_KEYS)
            }
            KeyLinkEvent.Removed -> {
                _ui.update { it.copy(key = KeyPresence.NONE) }
                if (machine != null) send(FlowEvent.KeyRemoved)
                else if (u.purpose == Purpose.RESET) Unit // los en weer in is hier juist de bedoeling
                else if (maintLink != null && u.maint != MaintStep.RESULT && u.maint != MaintStep.CONNECT) {
                    maintJob?.cancel()
                    toLocalStop(Stop.KEY_REMOVED)
                }
            }
        }
    }

    // ================================================================== afleiding scherm (machine)

    private fun send(e: FlowEvent) {
        if (machine == null) {
            if (e is FlowEvent.PinRetyped) e.retyped.wipe()
            if (e is FlowEvent.PinEntered) e.pin.wipe()
            return
        }
        events.trySend(e)
    }

    private fun recompute() {
        val u = _ui.value
        if (u.quit) return
        if (u.localStop != null) {
            if (u.screen != Screen.M11_STOP) {
                wipeAllSecrets()
                _ui.update { it.copy(screen = Screen.M11_STOP) }
            }
            return
        }
        val m = machine ?: return
        val profile = u.profile ?: return
        val st = u.machine ?: return
        if (st == State.Done) {
            wipeAllSecrets()
            _ui.update { it.copy(quit = true) }
            return
        }
        val minPending = Written.MIN_PIN_LENGTH_63 in (u.pending ?: emptySet())
        val screen = setupScreen(st, profile, u.busy, copyStep, resumeEntryOpen, minPending)
        val needEntry = when (screen) {
            Screen.M6_RETYPE -> EntryMode.RETYPE
            Screen.M8_PIN_ENTRY -> EntryMode.PAPER
            else -> null
        }
        var newEntry = u.entry
        if (needEntry == null) {
            entry?.wipe()
            entry = null
            newEntry = null
        } else if (entry == null || entry?.mode != needEntry) {
            entry?.wipe()
            val d = m as? DefaultSetupMachine
            val matcher: ((Int, CharArray) -> Boolean)? =
                if (needEntry == EntryMode.RETYPE && d != null) { g, typed -> d.retypedGroupMatches(g, typed) } else null
            val c = PinEntryController(needEntry, matcher)
            entry = c
            newEntry = c.ui
        }
        if (st is State.Stopped) wipeAllSecrets()
        _ui.update { it.copy(screen = screen, entry = newEntry) }
    }

    override fun onCleared() {
        wipeAllSecrets()
        try { wiper.close() } catch (e: Exception) { /* niets */ }
        try { discovery?.stop() } catch (e: Exception) { /* niets */ }
        events.close()
        super.onCleared()
    }

    override fun toString(): String = "HorseSafeViewModel(screen=${_ui.value.screen.code})"

    companion object {
        const val MAX_CODE = 12

        fun factory(services: AppServices): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T = HorseSafeViewModel(services) as T
        }
    }
}
