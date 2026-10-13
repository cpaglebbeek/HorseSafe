package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.PinCompare
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.CtapInfo
import nl.icthorse.horsesafe.yubikey.api.EnrollProgress
import nl.icthorse.horsesafe.yubikey.api.Enrollment
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.SensorFacts

/**
 * Inrichten (F2 hoofdsleutel, F3 noodsleutel) en hervatten (F2r/F3r) als pure toestandsmachine.
 *
 * Vaste volgorde (CallLog-test bewaakt hem):
 * - NEW: detectie → gate → PIN maken/tonen/hertypen → [attest vóór PIN: YK5, of Bio met alwaysUv=false]
 *   → setPin (teruglezen clientPin + 8 pogingen) → [attest na PIN: Bio met alwaysUv=true] → tellen
 *   (resident 0, vingers 0) → bevestigen → setMinPinLength(63) (teruglezen vers + ruw 0x0D)
 *   → alwaysUv (alleen toggelen bij false; teruglezen) → [YK5: U2F-controle, oranje] → [Bio-hoofd: 2-3 vingers]
 *   → eindinspectie (F4a-regels, zelfde sleutel) → rapport.
 * - RESUME: detectie → hervat-gate → PIN van papier → attest met token → tellen → de rest zoals NEW,
 *   met overslaan van wat al op de sleutel staat.
 *
 * Elke overgang gaat naar een hogere [State.order] of naar [State.Stopped]; na een stop doet de machine
 * niets meer op de sleutel. PIN's staan alleen in [SecretBuffer]s die de machine zelf wist.
 */
class DefaultSetupMachine(
    override val profile: Profile,
    override val mode: SetupMode,
    private val inspector: InspectorOps,
    private val judge: AttestationJudge,
    private val reports: ReportFactory,
    private val generator: PinGenerator = PinGenerator(),
    private val maxPinPolicy: MaxPinLengthPolicy = MaxPinLengthPolicy.ASSUME_CTAP21_MAX,
    private val enrollTimeoutMs: Int? = null,
) : SetupMachine {

    private val _state = MutableStateFlow<State>(State.Idle)
    override val state: StateFlow<State> = _state.asStateFlow()

    private val _history = mutableListOf<State>(State.Idle)
    /** Alle doorlopen staten (geen geheimen), voor tests en M11. */
    val history: List<State> get() = synchronized(_history) { _history.toList() }

    private val _notice = MutableStateFlow<Notice?>(null)
    val notice: StateFlow<Notice?> = _notice.asStateFlow()

    private val _fingers = MutableStateFlow<List<Enrollment>>(emptyList())
    /** Ingeschreven vingers (M7). */
    val fingers: StateFlow<List<Enrollment>> = _fingers.asStateFlow()

    private val _progress = MutableStateFlow<EnrollProgress?>(null)
    val enrollProgress: StateFlow<EnrollProgress?> = _progress.asStateFlow()

    private val mutex = Mutex()

    private var link: KeyLink? = null
    private var facts0: KeyFacts? = null
    /** Detectie- en gateregels plus latere regels (geen geheimen). */
    private val checks = mutableListOf<CheckResult>()
    private var violations: List<Stop> = emptyList()
    private var timing: AttestTiming = AttestTiming.AFTER_SET_PIN
    private var pending: Set<Written> = emptySet()
    private val written = linkedSetOf<Written>()

    /** Gegenereerde PIN (A); alleen tussen PinGenerated en PinRetypedOk. */
    private var pinA: SecretBuffer? = null
    /** Werkende PIN (B): hertypt (NEW) of van papier (RESUME). */
    private var pinB: SecretBuffer? = null

    private var attestLeaf: String? = null
    private var resident: Int? = null
    private var sensor: SensorFacts? = null
    private val untested = mutableSetOf<Enrollment>()
    private var finalFacts: KeyFacts? = null

    /** Feiten van de detectie (M2), null vóór KeyConnected. */
    val facts: KeyFacts? get() = facts0

    // ------------------------------------------------------------------ UI-toegang tot de PIN (M4/M5)

    /** M4: leent de gegenereerde PIN, alleen in [State.PinGenerated]. [block] mag hem niet bewaren. */
    fun <T> revealPin(block: (SecretBuffer) -> T): T? {
        val a = pinA ?: return null
        if (_state.value !is State.PinGenerated) return null
        return block(a)
    }

    /** M5: klopt hertypte groep [group] (0-based, 7 tekens)? Constante tijd; zegt nooit welk teken. */
    fun retypedGroupMatches(group: Int, typed: CharArray): Boolean {
        val a = pinA ?: return false
        if (_state.value !is State.PinShown || group !in 0 until GroupCheck.GROUPS) return false
        val tmp = CharArray(GroupCheck.GROUP_SIZE)
        return try {
            a.useChars { c -> System.arraycopy(c, group * GroupCheck.GROUP_SIZE, tmp, 0, GroupCheck.GROUP_SIZE) }
            PinCompare.equal(tmp, typed)
        } finally {
            tmp.fill('\u0000')
        }
    }

    override fun wipeSecrets() {
        pinA?.wipe(); pinA = null
        pinB?.wipe(); pinB = null
    }

    // ------------------------------------------------------------------ events

    override suspend fun handle(event: FlowEvent): State = mutex.withLock {
        try {
            process(event)
        } catch (e: Throwable) {
            ErrorMap.rethrowIfCancellation(e)
            stop(ErrorMap.stopFor(e))
        } finally {
            // Een buffer uit een event die de machine niet heeft overgenomen, wordt hoe dan ook gewist.
            when (event) {
                is FlowEvent.PinRetyped -> if (event.retyped !== pinB) event.retyped.wipe()
                is FlowEvent.PinEntered -> if (event.pin !== pinB) event.pin.wipe()
                else -> Unit
            }
        }
        _state.value
    }

    private suspend fun process(event: FlowEvent) {
        val s = _state.value
        if (s is State.Stopped || s is State.Done) {
            if (event is FlowEvent.Quit || event is FlowEvent.Cancel) wipeSecrets()
            return
        }
        when (event) {
            is FlowEvent.EnvironmentChecked -> onEnvironment(event.violations)
            is FlowEvent.KeyConnected -> onKeyConnected(event.link)
            FlowEvent.KeyRemoved -> if (link != null && s !is State.ReportReady) stop(Stop.KEY_REMOVED)
            FlowEvent.MultipleKeys -> if (s !is State.ReportReady) stop(Stop.MULTIPLE_KEYS)
            FlowEvent.ChecklistConfirmed -> onChecklist()
            FlowEvent.RevealFinished -> if (s is State.PinGenerated) to(State.PinShown)
            is FlowEvent.PinRetyped -> onRetyped(event.retyped)
            is FlowEvent.PinEntered -> onPinEntered(event.pin)
            FlowEvent.IrreversibleConfirmed -> if (s is State.CountsOk && Written.MIN_PIN_LENGTH_63 in pending) {
                to(State.ConfirmIrreversible); advance()
            }
            is FlowEvent.EnrollFinger -> onEnrollFinger(event.name)
            FlowEvent.FingersDone -> onFingersDone()
            FlowEvent.Retry -> { _notice.value = null; advance() }
            FlowEvent.Recreated -> onRecreated()
            FlowEvent.Cancel -> stop(Stop.CANCELLED)
            FlowEvent.Quit -> if (s is State.ReportReady) { wipeSecrets(); to(State.Done) } else stop(Stop.CANCELLED)
        }
    }

    private fun onEnvironment(v: List<Stop>) {
        violations = v.toList()
        when (val s = _state.value) {
            State.Idle -> to(State.EnvOk(v.map { CheckResult("omgeving_${it.name.lowercase()}", Verdict.RED, it.tekst) }))
            is State.PinGenerated, is State.PinShown -> if (v.isNotEmpty()) stop(v.first())
            else -> Unit.also { s }
        }
    }

    private suspend fun onKeyConnected(l: KeyLink) {
        val s = _state.value
        if (link != null) {
            if (s !is State.ReportReady) stop(Stop.MULTIPLE_KEYS)
            return
        }
        if (s !is State.EnvOk) {
            _notice.value = Notice("Eerst de omgeving controleren.")
            return
        }
        link = l
        val f = inspector.inspect(l)
        facts0 = f
        val det = DetectionPolicy.evaluate(f, profile, maxPinPolicy)
        checks += det.checks
        to(State.Detected(f, det.checks))
        det.stop?.let { stop(it); return }
        when (mode) {
            SetupMode.NEW -> {
                val g = Gates.newKey(f, profile)
                checks += g.checks
                g.stop?.let { stop(it); return }
                timing = profile.attestTiming(f.option("alwaysUv") == true)
                pending = Gates.pendingFromFacts(f, profile)
                to(State.GateNewOk)
            }
            SetupMode.RESUME -> {
                val (g, p) = Gates.resume(f, profile)
                checks += g.checks
                written += Written.PIN
                if (Written.MIN_PIN_LENGTH_63 !in p) written += Written.MIN_PIN_LENGTH_63
                if (f.option("alwaysUv") == true) written += Written.ALWAYS_UV
                if (f.option("bioEnroll") == true) written += Written.FINGERPRINTS
                g.stop?.let { stop(it); return }
                pending = p
                to(State.GateResumeOk(p))
            }
        }
    }

    private fun onChecklist() {
        if (_state.value !is State.GateNewOk) return
        if (violations.isNotEmpty()) { stop(violations.first()); return }
        pinA = generator.generate()
        to(State.PinGenerated)
    }

    private suspend fun onRetyped(b: SecretBuffer) {
        if (_state.value !is State.PinShown) return
        if (violations.isNotEmpty()) { stop(violations.first()); return }
        val a = pinA ?: run { stop(Stop.INTERNAL_ERROR); return }
        if (!PinGenerator.isWellFormed(b) || !PinCompare.equal(a, b)) {
            _notice.value = Notice("De hertypte PIN wijkt af. Controleer de groepen.")
            return
        }
        a.wipe(); pinA = null
        pinB = b
        to(State.PinRetypedOk)
        advance()
    }

    private suspend fun onPinEntered(p: SecretBuffer) {
        if (mode != SetupMode.RESUME || _state.value !is State.GateResumeOk || pinB != null) return
        if (violations.isNotEmpty()) { stop(violations.first()); return }
        if (!PinGenerator.isWellFormed(p)) {
            _notice.value = Notice("De PIN is niet compleet of bevat een ongeldig teken; er is geen poging gebruikt.")
            return
        }
        pinB = p
        advance()
    }

    private fun onRecreated() {
        val s = _state.value
        when {
            Written.PIN in written -> stop(Stop.PROCESS_RESTARTED)
            s is State.PinGenerated || s is State.PinShown || s is State.PinRetypedOk || s is State.AttestOkBeforePin ->
                stop(Stop.RESTART_BEFORE_PIN)
            else -> Unit
        }
    }

    // ------------------------------------------------------------------ automatische stappen

    private suspend fun advance() {
        while (true) {
            val step = nextStep(_state.value) ?: return
            try {
                step()
            } catch (e: Throwable) {
                ErrorMap.rethrowIfCancellation(e)
                if (ErrorMap.retriable(e)) { _notice.value = ErrorMap.noticeFor(e); return }
                throw e
            }
            if (_state.value is State.Stopped) return
        }
    }

    private fun nextStep(s: State): (suspend () -> Unit)? = when (s) {
        is State.GateResumeOk -> if (pinB != null) ({ resumeAttest() }) else null
        State.PinRetypedOk -> if (timing == AttestTiming.BEFORE_SET_PIN) ({ attest(before = true) }) else ({ setPin() })
        State.AttestOkBeforePin -> ({ setPin() })
        is State.PinSet -> if (timing == AttestTiming.AFTER_SET_PIN) ({ attest(before = false) }) else ({ counts() })
        State.AttestOkAfterPin -> ({ counts() })
        is State.CountsOk -> if (Written.MIN_PIN_LENGTH_63 in pending) null else ({ alwaysUv() })
        State.ConfirmIrreversible -> ({ setMinPinLength() })
        State.MinLenSet -> ({ alwaysUv() })
        State.AlwaysUvOk -> when (profile) {
            Profile.RECOVERY_YK5 -> ({ u2fCheck() })
            Profile.BIO_MAIN -> null // wacht op EnrollFinger / FingersDone
            Profile.RECOVERY_BIO -> ({ finalInspect() })
        }
        is State.U2fChecked -> ({ finalInspect() })
        is State.FingersOk -> ({ finalInspect() })
        State.FinalInspect -> ({ makeReport() })
        else -> null
    }

    private fun requireLink(): KeyLink = link ?: throw FlowStop(Stop.INTERNAL_ERROR)
    private fun requirePin(): SecretBuffer = pinB?.takeIf { !it.isWiped } ?: throw FlowStop(Stop.INTERNAL_ERROR)
    private fun requireFacts(): KeyFacts = facts0 ?: throw FlowStop(Stop.INTERNAL_ERROR)

    private fun expect(f: KeyFacts, withToken: Boolean) =
        AttestExpectation(f.aaguid, f.keyClass, requireUv = withToken, rpId = AttestOps.KEURING_RP_ID)

    private fun judge(ev: nl.icthorse.horsesafe.yubikey.api.AttestationEvidence, withToken: Boolean) {
        val f = requireFacts()
        if (ev.withToken != withToken || ev.rpId != AttestOps.KEURING_RP_ID) throw FlowStop(Stop.ATTEST_RP_ID_HASH)
        when (val o = judge.judge(ev, expect(f, withToken))) {
            is AttestOutcome.Ok -> {
                attestLeaf = o.leafSha256
                checks += CheckResult("attestation", Verdict.GREEN, "Echtheid aangetoond (Yubico-certificaat).")
            }
            is AttestOutcome.Failed -> throw FlowStop(o.stop)
        }
    }

    /** F2.5 / F3: keurings-makeCredential op de wegwerp-rpId. */
    private suspend fun attest(before: Boolean) {
        val l = requireLink()
        val ev = try {
            if (before) l.ctap { attest.keuringCredential(null) }
            else {
                val p = requirePin()
                l.ctap { pin.pinToken(p, Permission.MC, AttestOps.KEURING_RP_ID).use { attest.keuringCredential(it) } }
            }
        } catch (e: KeyError.PinInvalid) {
            throw FlowStop(Stop.PIN_READBACK_FAILED)
        }
        judge(ev, withToken = !before)
        to(if (before) State.AttestOkBeforePin else State.AttestOkAfterPin)
    }

    /** RESUME: PIN van papier bewijzen via een MC-token en meteen de keuring doen. */
    private suspend fun resumeAttest() {
        val l = requireLink()
        val p = requirePin()
        val ev = try {
            l.ctap { pin.pinToken(p, Permission.MC, AttestOps.KEURING_RP_ID).use { attest.keuringCredential(it) } }
        } catch (e: KeyError.PinInvalid) {
            p.wipe(); pinB = null
            val left = e.retriesLeft
            _notice.value = Notice("De PIN klopt niet. Controleer het papier met de controletekens.", left)
            when {
                left == 0 -> stop(Stop.PIN_BLOCKED)
                left == null || left <= Limits.PIN_RETRIES_BLOCK_AT -> stop(Stop.PIN_RETRIES_LOW)
            }
            return
        }
        judge(ev, withToken = true)
        to(State.AttestOkAfterPin)
    }

    /** F2.4: setPin en vers teruglezen. */
    private suspend fun setPin() {
        val l = requireLink()
        val p = requirePin()
        if (!PinGenerator.isWellFormed(p)) throw FlowStop(Stop.INTERNAL_ERROR)
        // Opnieuw na een herstelbare fout (time-out, afgebroken)? Dan kan de sleutel setPin al hebben
        // uitgevoerd terwijl het antwoord verloren ging (review-bevinding).
        val retry = Written.PIN in written
        written += Written.PIN // conservatief: bij een verbroken verbinding is onbekend of hij staat
        val info: CtapInfo = try {
            l.ctap {
                pin.setPin(p)
                freshInfo()
            }
        } catch (e: KeyError.PinPolicyViolation) {
            if (!retry) written -= Written.PIN
            throw FlowStop(if (requireFacts().pinComplexity == true) Stop.PIN_POLICY_COMPLEXITY else Stop.PIN_POLICY_MPE_PIV)
        } catch (e: KeyError.OperationDenied) {
            // Bij een herhaling staat er nu een PIN: vrijwel zeker die van dit formulier. Niet uit
            // [written] halen; advies = hervatten met het papier.
            if (retry) throw FlowStop(Stop.PIN_STATE_UNKNOWN)
            written -= Written.PIN
            throw FlowStop(Stop.PIN_ALREADY_SET)
        }
        val retries = info.pinRetries
        if (info.options["clientPin"] != true || retries != Limits.FULL_PIN_RETRIES) throw FlowStop(Stop.PIN_READBACK_FAILED)
        to(State.PinSet(retries))
    }

    /** F2.6: resident credentials (CM) en vingers (BE), elk met een eigen token. */
    private suspend fun counts() {
        val l = requireLink()
        val p = requirePin()
        val bio = requireFacts().keyClass == KeyClass.BIO
        val (r, list) = try {
            l.ctap {
                val r = pin.pinToken(p, Permission.CM).use { credMgmt.metadata(it) }.existingResidentCredentials
                val list = if (bio) pin.pinToken(p, Permission.BE).use { t -> sensor = this.bio.sensorInfo(t); this.bio.enumerate(t) } else emptyList()
                r to list
            }
        } catch (e: KeyError.PinInvalid) {
            throw FlowStop(Stop.PIN_READBACK_FAILED)
        }
        resident = r
        if (r != 0) throw FlowStop(Stop.KEY_ALREADY_USED)
        when (mode) {
            SetupMode.NEW -> if (list.isNotEmpty()) throw FlowStop(Stop.KEY_ALREADY_USED)
            SetupMode.RESUME -> {
                if (profile == Profile.RECOVERY_BIO && list.isNotEmpty()) throw FlowStop(Stop.RECOVERY_BIO_HAS_FINGER)
                if (profile == Profile.BIO_MAIN && list.size > profile.fingers.last) throw FlowStop(Stop.FINGER_COUNT_INVALID)
                val needFingers = profile == Profile.BIO_MAIN && list.size < profile.fingers.first
                if (pending.isEmpty() && !needFingers) throw FlowStop(Stop.RESUME_NOT_ALLOWED)
            }
        }
        _fingers.value = list
        to(State.CountsOk(r, list.size))
    }

    /** F2.7: minimum 63, alleen na [State.ConfirmIrreversible]; teruglezen vers én ruw (0x0D). */
    private suspend fun setMinPinLength() {
        val l = requireLink()
        val p = requirePin()
        written += Written.MIN_PIN_LENGTH_63
        val info = try {
            l.ctap {
                pin.pinToken(p, Permission.ACFG).use { config.setMinPinLength63(it) }
                freshInfo()
            }
        } catch (e: KeyError.PinPolicyViolation) {
            written -= Written.MIN_PIN_LENGTH_63
            throw FlowStop(Stop.MIN_PIN_LENGTH_READBACK_FAILED)
        } catch (e: KeyError.NotSupported) {
            written -= Written.MIN_PIN_LENGTH_63
            throw FlowStop(Stop.MISSING_SET_MIN_PIN_LENGTH)
        } catch (e: KeyError.PinInvalid) {
            written -= Written.MIN_PIN_LENGTH_63
            throw FlowStop(Stop.PIN_READBACK_FAILED)
        }
        if (info.minPinLength != Limits.PIN_LENGTH || info.forcePinChange) throw FlowStop(Stop.MIN_PIN_LENGTH_READBACK_FAILED)
        val raw = l.readRawInfo()
        if (!raw.present.minPinLength0x0D || raw.minPinLength != Limits.PIN_LENGTH || raw.forcePinChange == true) {
            throw FlowStop(Stop.MIN_PIN_LENGTH_READBACK_FAILED)
        }
        to(State.MinLenSet)
    }

    /** F2.8: alwaysUv alleen toggelen bij false; altijd vers teruglezen. */
    private suspend fun alwaysUv() {
        val l = requireLink()
        val p = requirePin()
        // Binnen een ctap-blok nooit FlowStop gooien: de link vertaalt elke exceptie naar KeyError.
        val info = l.ctap {
            val before = freshInfo()
            if (before.options["alwaysUv"] == false) {
                written += Written.ALWAYS_UV
                pin.pinToken(p, Permission.ACFG).use { config.toggleAlwaysUvIfFalse(it) }
                freshInfo()
            } else before
        }
        if (info.options["alwaysUv"] == null) throw FlowStop(Stop.MISSING_ALWAYS_UV)
        if (info.options["alwaysUv"] != true) throw FlowStop(Stop.ALWAYS_UV_READBACK_FAILED)
        written += Written.ALWAYS_UV
        if (profile == Profile.RECOVERY_BIO) {
            checks += CheckResult(
                "u2f_after_always_uv", Verdict.GREEN,
                if ("U2F_V2" in info.versions) "U2F_V2 blijft op de Bio (toegestaan, vastgelegd)." else "U2F_V2 niet gemeld.",
            )
        }
        to(State.AlwaysUvOk)
    }

    /** F3: na alwaysUv hoort U2F_V2 weg te zijn op een YubiKey 5; anders oranje (kritiek 10). */
    private suspend fun u2fCheck() {
        val info = requireLink().ctap { freshInfo() }
        val still = "U2F_V2" in info.versions
        checks += CheckResult(
            "u2f_after_always_uv", if (still) Verdict.ORANGE else Verdict.GREEN,
            if (still) "U2F_V2 staat nog in versions na alwaysUv (afwijkend, vastgelegd)." else "U2F_V2 is weg na alwaysUv.",
        )
        to(State.U2fChecked(still))
    }

    // ------------------------------------------------------------------ vingers (F2.9)

    private suspend fun onEnrollFinger(name: String) {
        if (profile != Profile.BIO_MAIN || _state.value !is State.AlwaysUvOk) return
        val current = _fingers.value
        if (current.size >= profile.fingers.last) {
            _notice.value = Notice("Er staan al ${current.size} vingers; meer is bij het inrichten niet nodig.")
            return
        }
        val maxBytes = sensor?.maxFriendlyNameBytes?.takeIf { it > 0 } ?: Limits.DEFAULT_FRIENDLY_NAME_BYTES
        if (!FingerNames.valid(name, maxBytes) || current.any { it.name == name }) {
            _notice.value = Notice("Ongeldige of dubbele naam (alleen ASCII, maximaal $maxBytes tekens).")
            return
        }
        val l = requireLink()
        val p = requirePin()
        val hadFingers = Written.FINGERPRINTS in written
        written += Written.FINGERPRINTS
        val list: Pair<nl.icthorse.horsesafe.yubikey.api.TemplateId, List<Enrollment>> = try {
            l.ctap {
                pin.pinToken(p, Permission.BE).use { t ->
                    val id = bio.enroll(t, name, enrollTimeoutMs) { _progress.value = it }
                    id to bio.enumerate(t)
                }
            }
        } catch (e: Throwable) {
            ErrorMap.rethrowIfCancellation(e)
            if (ErrorMap.retriable(e)) {
                if (!hadFingers) written -= Written.FINGERPRINTS
                _notice.value = ErrorMap.noticeFor(e)
                return
            }
            throw e
        } finally {
            _progress.value = null
        }
        val (newId, after) = list
        if (after.size != current.size + 1 || after.none { it.templateId == newId }) throw FlowStop(Stop.FINGER_COUNT_INVALID)
        _fingers.value = after
        val added = after.filter { it !in current }
        untested += added
        testTouch()
    }

    /** Testaanraking: UV-token (MC, wegwerp-rpId) en daarna uvRetries teruglezen. */
    private suspend fun testTouch(): Boolean {
        val l = requireLink()
        return try {
            l.ctap {
                pin.uvToken(Permission.MC, AttestOps.KEURING_RP_ID).use { }
                pin.uvRetries()
            }
            untested.clear()
            testedOnce = true
            _notice.value = Notice("Testaanraking geslaagd.")
            true
        } catch (e: Throwable) {
            ErrorMap.rethrowIfCancellation(e)
            when {
                ErrorMap.retriable(e) || e is KeyError.UvInvalid -> {
                    _notice.value = Notice("Testaanraking mislukt; probeer het bij \"Klaar\" opnieuw.")
                    false
                }
                e is KeyError.UvBlocked -> {
                    // CTAP 2.1: een geslaagd PIN-token met permissies zet uvRetries terug op het maximum.
                    recoverUvWithPin(l)
                    _notice.value = Notice("Vingerpogingen op; met de PIN hersteld. Probeer de testaanraking opnieuw.")
                    false
                }
                else -> throw e
            }
        }
    }

    /** UV_BLOCKED herstellen: BE-token met de PIN (geen bijwerking), zet uvRetries terug. */
    private suspend fun recoverUvWithPin(l: KeyLink) {
        val p = requirePin()
        try {
            l.ctap { pin.pinToken(p, Permission.BE).use { } }
        } catch (e: KeyError.PinInvalid) {
            throw FlowStop(Stop.PIN_READBACK_FAILED)
        }
    }

    private suspend fun onFingersDone() {
        if (profile != Profile.BIO_MAIN || _state.value !is State.AlwaysUvOk) return
        val list = _fingers.value
        if (list.size !in profile.fingers) {
            _notice.value = Notice("Schrijf ${profile.fingers.first} of ${profile.fingers.last} vingers in, verdeeld over beide handen.")
            return
        }
        if (untested.isNotEmpty() || !testedOnce) {
            if (!testTouch()) return
        }
        val l = requireLink()
        val p = requirePin()
        val (info, readBack) = l.ctap {
            val again = pin.pinToken(p, Permission.BE).use { bio.enumerate(it) }
            freshInfo() to again
        }
        if (info.options["bioEnroll"] != true || readBack.toSet() != list.toSet()) throw FlowStop(Stop.FINGER_COUNT_INVALID)
        to(State.FingersOk(list.size))
        advance()
    }

    private var testedOnce = false

    // ------------------------------------------------------------------ einde

    /** Eindinspectie met de F4a-regels; zelfde sleutel als bij de detectie. */
    private suspend fun finalInspect() {
        val f0 = requireFacts()
        val f = inspector.inspect(requireLink())
        if (f.aaguid != f0.aaguid || f.serialHmac != f0.serialHmac) throw FlowStop(Stop.KEY_SWAPPED)
        val fingerCount = if (f.keyClass == KeyClass.BIO) _fingers.value.size else null
        val k = KeuringRules.evaluate(f, profile, fingerCount)
        checks += k.checks
        k.stop?.let { throw FlowStop(it) }
        finalFacts = f
        to(State.FinalInspect)
    }

    private fun makeReport() {
        val f = finalFacts ?: throw FlowStop(Stop.INTERNAL_ERROR)
        val report = reports.build(
            kind = if (mode == SetupMode.NEW) ReportKind.SETUP else ReportKind.RESUME,
            profile = profile,
            facts = f,
            checks = checks.toList(),
            m = Measured(
                residentCredentials = resident,
                fingers = if (f.keyClass == KeyClass.BIO) _fingers.value else null,
                attestationOk = attestLeaf != null,
                attestationLeafSha256 = attestLeaf,
            ),
        )
        wipeSecrets()
        to(State.ReportReady(report))
    }

    // ------------------------------------------------------------------ overgangen

    private fun to(next: State) {
        val cur = _state.value
        check(next is State.Stopped || next.order > cur.order) { "terugwaartse overgang ${cur.order} -> ${next.order}" }
        _state.value = next
        synchronized(_history) { _history += next }
    }

    private fun stop(s: Stop) {
        wipeSecrets()
        if (_state.value is State.Stopped) return
        to(State.Stopped(s, written.toSet(), _fingers.value.size))
    }
}
