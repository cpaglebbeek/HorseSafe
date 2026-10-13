package nl.icthorse.horsesafe.flow.fake

import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.AlwaysUvOutcome
import nl.icthorse.horsesafe.yubikey.api.Applet
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.AttestationEvidence
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.BioEnrollOps
import nl.icthorse.horsesafe.yubikey.api.ConfigOps
import nl.icthorse.horsesafe.yubikey.api.CredMetadata
import nl.icthorse.horsesafe.yubikey.api.CredMgmtOps
import nl.icthorse.horsesafe.yubikey.api.CtapInfo
import nl.icthorse.horsesafe.yubikey.api.CtapPhase
import nl.icthorse.horsesafe.yubikey.api.EnrollProgress
import nl.icthorse.horsesafe.yubikey.api.Enrollment
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyFormFactor
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.ManagementFacts
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.PinOps
import nl.icthorse.horsesafe.yubikey.api.PinRetries
import nl.icthorse.horsesafe.yubikey.api.RawGetInfo
import nl.icthorse.horsesafe.yubikey.api.RawPresence
import nl.icthorse.horsesafe.yubikey.api.ResetOps
import nl.icthorse.horsesafe.yubikey.api.SampleFeedback
import nl.icthorse.horsesafe.yubikey.api.SensorFacts
import nl.icthorse.horsesafe.yubikey.api.TemplateId
import nl.icthorse.horsesafe.yubikey.api.Transport

/** Vaste eigenschappen van een gesimuleerde sleutel (profielen in [KeyProfiles]). */
data class KeySpec(
    val name: String,
    val aaguid: Aaguid,
    val firmware: Firmware?,
    val formFactor: KeyFormFactor,
    val serial: Int?,
    val versions: List<String>,
    val bio: Boolean,
    /** Begintoestand van alwaysUv; null = optie bestaat niet. */
    val alwaysUv: Boolean?,
    val setMinPinLengthOption: Boolean = true,
    val authnrCfg: Boolean = true,
    val maxRpids: Int = 1,
    /** Werkelijk maximum dat setPin accepteert (MPE met PIV: 8). */
    val maxPinActual: Int = 63,
    /** 0x1D in de ruwe getInfo. Standaard false: YubiKey-firmware 5.7 (CTAP 2.1) meldt het niet (gemeten 13-10-2026). */
    val maxPinReported: Boolean = false,
    val managementAvailable: Boolean = true,
    val pinComplexity: Boolean = false,
    val attFmt: String = "packed",
    /** false = keten naar een vreemde CA (nagemaakte sleutel). */
    val genuine: Boolean = true,
    /** CTAP 2.1 §7.2.4: U2F_V2 verdwijnt bij alwaysUv; true = afwijkende sleutel. */
    val u2fStaysAfterAlwaysUv: Boolean = false,
    /** Sleutel die minimum 63 (= maximum) weigert (onzekerheid 2). */
    val refusesMin63: Boolean = false,
    val transport: Transport = Transport.USB,
    /** PIN-pogingen die de sleutel meldt zolang er GEEN PIN op staat; null = niet gemeld (0.3.3). */
    val retriesWithoutPin: Int? = 8,
)

/**
 * CTAP 2.1-gedrag op het niveau van de ops-interfaces (geen CBOR):
 * - 8 PIN-pogingen; na 3 fouten op rij [KeyError.PinAuthBlocked] tot [reinsert]; 0 = [KeyError.PinBlocked];
 * - minimum alleen omhoog; als de huidige PIN korter is dan het nieuwe minimum → forcePinChange;
 * - alwaysUv-toggle; bij een YubiKey 5 verdwijnt U2F_V2 (tenzij [KeySpec.u2fStaysAfterAlwaysUv]);
 * - maximaal 5 templates; enroll meldt `remainingSamples` en CaptureErrors;
 * - tokens met precies één permissie, geldig binnen één CTAP-fase; een token zonder permissie faalt ([rawPinToken]);
 * - makeCredential zonder token alleen zolang alwaysUv uit is en (geen PIN of makeCredUvNotRqd).
 * Elke aanroep komt in [log]; [crashAfter] laat de sleutel ná een geslaagde aanroep "uitgetrokken" worden.
 */
class FakeYubiKey(val spec: KeySpec) : KeyLink {
    // ---- toestand op de sleutel
    var pin: CharArray? = null
        private set
    var pinRetries = 8
        private set
    private var consecutiveFails = 0
    var powerCycleRequired = false
        private set
    var minPinLength = 4
        private set
    var forcePinChange = false
        private set
    var minPinRpIds: List<String> = emptyList()
        private set
    var alwaysUv: Boolean? = spec.alwaysUv
        private set
    val versions: MutableList<String> = spec.versions.toMutableList()
    private val templates = LinkedHashMap<TemplateId, String?>()
    private var nextTemplate = 1
    var residentCredentials = 0
    var uvRetries = 3
        private set
    val makeCredUvNotRqd = true

    // ---- testbesturing
    val log = mutableListOf<String>()
    /** Naam (prefix) van een aanroep; na de [crashAfterNth]-de geslaagde treffer wordt de sleutel uitgetrokken. */
    var crashAfter: String? = null
    var crashAfterNth: Int = 1
    private var crashHits = 0
    /** false = gebruiker raakt niet aan → UserActionTimeout bij makeCredential/enroll/uvToken. */
    var touchResponds = true
    /** false = vinger niet herkend bij de testaanraking. */
    var fingerMatches = true
    /** CaptureErrors die de volgende enroll eerst meldt. */
    val captureErrors = ArrayDeque<SampleFeedback>()
    /** Liegt bij teruglezen: minimum blijft schijnbaar ongewijzigd. */
    var lieAboutMinPinLength = false
    /** Toggle wordt genegeerd (teruglezen faalt). */
    var ignoreToggle = false
    /** setPin wordt uitgevoerd, maar het antwoord gaat verloren (time-out); eenmalig. */
    var timeoutAfterSetPin = false
    /** Testhulp: zet de vingerpogingen (bv. 0 = UV_BLOCKED). */
    fun setUvRetries(n: Int) { uvRetries = n }
    /** Resetvenster (CTAP: alleen kort na insteken): open bij aanmaken en na [reinsert]; [closeResetWindow] = te laat. */
    var resetWindowOpen = true
        private set
    fun closeResetWindow() { resetWindowOpen = false }
    /** De volgende testaanraking mislukt en zet uvRetries op 0 (UV_BLOCKED); eenmalig. */
    var uvBlockOnNextTouch = false

    private val _connected = MutableStateFlow(true)
    override val isConnected: StateFlow<Boolean> = _connected
    override val transport: Transport get() = spec.transport

    private var phaseSeq = 0
    private var activePhase = -1
    private var tokenEpoch = 0
    private val liveTokens = mutableListOf<FakeToken>()

    // ---- testhulpen
    /** Zet de sleutel in een "gebruikte" toestand zonder via de flows te gaan. */
    fun preset(pin: CharArray? = null, fingers: List<String> = emptyList(), resident: Int = 0, minLen: Int? = null,
               alwaysUvOn: Boolean? = null, retries: Int? = null, forceChange: Boolean = false) {
        this.pin = pin?.copyOf()
        fingers.forEach { templates[TemplateId(byteArrayOf(nextTemplate++.toByte()))] = it }
        residentCredentials = resident
        minLen?.let { minPinLength = it; minPinRpIds = listOf(ConfigOps.MIN_PIN_RP_ID) }
        alwaysUvOn?.let { setAlwaysUv(it) }
        retries?.let { pinRetries = it }
        forcePinChange = forceChange
    }

    val fingerCount: Int get() = templates.size
    fun fingerNames(): List<String?> = templates.values.toList()
    fun pinEquals(p: CharArray): Boolean = pin?.contentEquals(p) == true

    fun unplug() { _connected.value = false }

    /** Opnieuw insteken: verbinding terug, power-cycle-blokkade (3 fouten op rij) weg. */
    fun reinsert() {
        _connected.value = true
        powerCycleRequired = false
        consecutiveFails = 0
        crashAfter = null
        resetWindowOpen = true
    }

    fun writes(): List<String> = log.filter { it in WRITE_OPS || it.startsWith("enroll") || it.startsWith("rename") || it.startsWith("remove") }

    // ---- KeyLink
    override suspend fun readManagement(): ManagementFacts? = op("readManagement") {
        if (!spec.managementAvailable) null
        else ManagementFacts(
            firmware = spec.firmware,
            formFactor = spec.formFactor,
            serial = spec.serial,
            pinComplexity = spec.pinComplexity,
            enabledApplets = mapOf(spec.transport to setOf(Applet.FIDO2, Applet.U2F)),
        )
    }

    override suspend fun readRawInfo(): RawGetInfo = op("readRawInfo") {
        val reportedMin = if (lieAboutMinPinLength) 4 else minPinLength
        RawGetInfo(
            present = RawPresence(forcePinChange0x0C = true, minPinLength0x0D = true, firmwareVersion0x0E = false, maxPinLength0x1D = spec.maxPinReported),
            keys = buildSet { addAll(listOf(1, 2, 3, 4, 5, 6, 0x0C, 0x0D)); if (spec.maxPinReported) add(0x1D) },
            forcePinChange = forcePinChange,
            minPinLength = reportedMin,
            firmwareVersion = null,
            maxPinLength = if (spec.maxPinReported) spec.maxPinActual else null,
        )
    }

    override suspend fun <T> ctap(block: suspend CtapPhase.() -> T): T {
        ensureConnected()
        val id = ++phaseSeq
        activePhase = id
        try {
            return FakePhase(id).block()
        } catch (e: Throwable) {
            // Zoals de echte link: alles wat geen KeyError is, wordt een Protocol-fout.
            if (e is CancellationException || e is KeyError) throw e
            throw KeyError.Protocol(e.javaClass.simpleName.ifEmpty { "onbekend" })
        } finally {
            liveTokens.filter { it.phase == id }.forEach { it.wipe() }
            liveTokens.removeAll { it.phase == id }
            activePhase = -1
        }
    }

    /** CTAP getPinUvAuthTokenUsingPinWithPermissions (0x09) met ruwe permissies; null/0 faalt zoals op een echte sleutel. */
    fun rawPinToken(pinChars: CharArray, permissions: Int?) {
        log += "rawPinToken(${permissions ?: "null"})"
        if (permissions == null) throw KeyError.Ctap(0x14) // MISSING_PARAMETER
        if (permissions == 0) throw KeyError.Ctap(0x02) // INVALID_PARAMETER
        verifyPin(pinChars)
    }

    // ---- intern

    private fun ensureConnected() {
        if (!_connected.value) throw KeyError.Disconnected()
    }

    private inline fun <T> op(name: String, body: () -> T): T {
        ensureConnected()
        val r = body()
        log += name
        val c = crashAfter
        if (c != null && name.startsWith(c)) {
            crashHits++
            if (crashHits >= crashAfterNth) {
                unplug()
                throw KeyError.Disconnected()
            }
        }
        return r
    }

    private fun setAlwaysUv(on: Boolean) {
        alwaysUv = on
        if (on && !spec.bio && !spec.u2fStaysAfterAlwaysUv) versions.remove("U2F_V2")
    }

    private fun options(): Map<String, Boolean> = buildMap {
        put("rk", true)
        put("up", true)
        put("plat", false)
        put("clientPin", pin != null)
        put("credMgmt", true)
        put("pinUvAuthToken", true)
        put("makeCredUvNotRqd", makeCredUvNotRqd)
        if (spec.authnrCfg) put("authnrCfg", true)
        if (spec.setMinPinLengthOption) put("setMinPINLength", true)
        alwaysUv?.let { put("alwaysUv", it) }
        if (spec.bio) {
            put("bioEnroll", templates.isNotEmpty())
            put("uv", templates.isNotEmpty())
        }
    }

    private fun verifyPin(p: CharArray) {
        val cur = pin ?: throw KeyError.PinNotSet()
        if (pinRetries == 0) throw KeyError.PinBlocked()
        if (powerCycleRequired) throw KeyError.PinAuthBlocked()
        if (!cur.contentEquals(p)) {
            pinRetries--
            consecutiveFails++
            if (pinRetries == 0) throw KeyError.PinBlocked()
            if (consecutiveFails >= 3) { powerCycleRequired = true; throw KeyError.PinAuthBlocked() }
            throw KeyError.PinInvalid(pinRetries)
        }
        pinRetries = 8
        consecutiveFails = 0
    }

    private fun checkPinPolicy(p: CharArray) {
        if (p.size < minPinLength || p.size > spec.maxPinActual) throw KeyError.PinPolicyViolation()
        if (spec.pinComplexity && p.toSet().size < 2) throw KeyError.PinPolicyViolation()
    }

    private fun validate(token: AuthToken, phase: Int, perm: Permission, rpId: String? = null) {
        val t = token as? FakeToken ?: throw KeyError.TokenInvalid()
        if (t.isWiped || t.phase != phase || t.phase != activePhase || t.epoch != tokenEpoch || t.permission != perm) throw KeyError.TokenInvalid()
        if (rpId != null && t.rpId != rpId) throw KeyError.TokenInvalid()
    }

    private fun touch() {
        if (!touchResponds) throw KeyError.UserActionTimeout()
    }

    private inner class FakeToken(override val permission: Permission, override val rpId: String?, val phase: Int, val epoch: Int) : AuthToken {
        private var wiped = false
        override val isWiped: Boolean get() = wiped
        override fun wipe() { wiped = true }
        override fun toString(): String = "FakeToken($permission)"
    }

    private inner class FakePhase(val id: Int) : CtapPhase {
        override val transport: Transport get() = spec.transport

        override suspend fun freshInfo(): CtapInfo = op("freshInfo") {
            CtapInfo(
                aaguid = spec.aaguid,
                versions = versions.toList(),
                options = options(),
                minPinLength = if (lieAboutMinPinLength) 4 else minPinLength,
                forcePinChange = forcePinChange,
                maxRpidsForSetMinPinLength = spec.maxRpids,
                pinUvAuthProtocols = listOf(2, 1),
                uvModality = if (spec.bio) 2 else null,
                pinRetries = if (this@FakeYubiKey.pin == null) spec.retriesWithoutPin else pinRetries,
                pinPowerCycleRequired = powerCycleRequired,
                uvRetries = if (spec.bio) uvRetries else null,
            )
        }

        override val pin: PinOps = object : PinOps {
            override suspend fun pinRetries(): PinRetries = op("pinRetries") { PinRetries(this@FakeYubiKey.pinRetries, powerCycleRequired) }

            override suspend fun uvRetries(): Int = op("uvRetries") {
                if (!spec.bio) throw KeyError.NotSupported("uv")
                this@FakeYubiKey.uvRetries
            }

            override suspend fun setPin(pin: SecretBuffer) = op("setPin") {
                if (this@FakeYubiKey.pin != null) throw KeyError.OperationDenied()
                pin.useChars { c ->
                    checkPinPolicy(c)
                    this@FakeYubiKey.pin = c.copyOf()
                }
                pinRetries = 8
                consecutiveFails = 0
                forcePinChange = false
                if (timeoutAfterSetPin) {
                    timeoutAfterSetPin = false
                    throw KeyError.UserActionTimeout()
                }
            }

            override suspend fun changePin(current: SecretBuffer, new: SecretBuffer) = op("changePin") {
                current.useChars { verifyPin(it) }
                new.useChars { c ->
                    checkPinPolicy(c)
                    this@FakeYubiKey.pin = c.copyOf()
                }
                forcePinChange = false
                tokenEpoch++
                Unit
            }

            override suspend fun pinToken(pin: SecretBuffer, permission: Permission, rpId: String?): AuthToken = op("pinToken:${permission.name}") {
                if (permission == Permission.MC && rpId == null) throw KeyError.Ctap(0x14)
                if (forcePinChange) throw KeyError.PinPolicyViolation()
                pin.useChars { verifyPin(it) }
                // CTAP 2.1: een geslaagd PIN-token met permissies zet ook uvRetries terug op het maximum.
                if (spec.bio) this@FakeYubiKey.uvRetries = 3
                FakeToken(permission, rpId, id, tokenEpoch).also { liveTokens += it }
            }

            override suspend fun uvToken(permission: Permission, rpId: String?): AuthToken = op("uvToken:${permission.name}") {
                if (!spec.bio || templates.isEmpty()) throw KeyError.NotSupported("uv")
                if (this@FakeYubiKey.uvRetries == 0) throw KeyError.UvBlocked()
                touch()
                if (uvBlockOnNextTouch) {
                    uvBlockOnNextTouch = false
                    this@FakeYubiKey.uvRetries = 0
                    throw KeyError.UvBlocked()
                }
                if (!fingerMatches) {
                    this@FakeYubiKey.uvRetries--
                    if (this@FakeYubiKey.uvRetries == 0) throw KeyError.UvBlocked()
                    throw KeyError.UvInvalid(this@FakeYubiKey.uvRetries)
                }
                this@FakeYubiKey.uvRetries = 3
                FakeToken(permission, rpId, id, tokenEpoch).also { liveTokens += it }
            }
        }

        override val config: ConfigOps = object : ConfigOps {
            override suspend fun setMinPinLength63(token: AuthToken) = op("setMinPinLength") {
                validate(token, id, Permission.ACFG)
                if (!spec.setMinPinLengthOption) throw KeyError.NotSupported("setMinPINLength")
                val n = ConfigOps.MIN_PIN_LENGTH
                if (n < minPinLength || spec.refusesMin63) throw KeyError.PinPolicyViolation()
                minPinLength = n
                minPinRpIds = listOf(ConfigOps.MIN_PIN_RP_ID)
                val p = this@FakeYubiKey.pin
                if (p != null && p.size < n) forcePinChange = true
            }

            override suspend fun toggleAlwaysUvIfFalse(token: AuthToken): AlwaysUvOutcome = op("toggleAlwaysUv") {
                validate(token, id, Permission.ACFG)
                when (alwaysUv) {
                    null -> throw KeyError.NotSupported("alwaysUv")
                    true -> AlwaysUvOutcome.ALREADY_ON
                    false -> {
                        if (!ignoreToggle) setAlwaysUv(true)
                        AlwaysUvOutcome.TURNED_ON
                    }
                }
            }
        }

        override val bio: BioEnrollOps = object : BioEnrollOps {
            private fun need(token: AuthToken) {
                if (!spec.bio) throw KeyError.NotSupported("bioEnroll")
                validate(token, id, Permission.BE)
            }

            override suspend fun sensorInfo(token: AuthToken): SensorFacts = op("sensorInfo") {
                need(token)
                SensorFacts(fingerprintKind = 1, maxCaptureSamplesRequiredForEnroll = 4, maxFriendlyNameBytes = 15)
            }

            override suspend fun enumerate(token: AuthToken): List<Enrollment> = op("enumerate") {
                need(token)
                templates.map { (k, v) -> Enrollment(k, v) }
            }

            override suspend fun enroll(token: AuthToken, name: String?, timeoutMs: Int?, onProgress: (EnrollProgress) -> Unit): TemplateId = op("enroll") {
                need(token)
                if (templates.size >= 5) throw KeyError.Ctap(0x17) // FP_DATABASE_FULL
                touch()
                var remaining = 4
                while (remaining > 0) {
                    val err = captureErrors.removeFirstOrNull()
                    if (err != null) onProgress(EnrollProgress(err, remaining))
                    else { remaining--; onProgress(EnrollProgress(SampleFeedback.GOOD, remaining)) }
                }
                val tid = TemplateId(byteArrayOf(nextTemplate++.toByte()))
                templates[tid] = name
                tid
            }

            override suspend fun rename(token: AuthToken, templateId: TemplateId, name: String) = op("rename") {
                need(token)
                if (templateId !in templates) throw KeyError.Ctap(0x2E) // NO_CREDENTIALS
                templates[templateId] = name
            }

            override suspend fun remove(token: AuthToken, templateId: TemplateId) = op("remove") {
                need(token)
                if (templates.remove(templateId) == null) throw KeyError.Ctap(0x2E)
                Unit
            }
        }

        override val credMgmt: CredMgmtOps = object : CredMgmtOps {
            override suspend fun metadata(token: AuthToken): CredMetadata = op("metadata") {
                validate(token, id, Permission.CM)
                CredMetadata(residentCredentials, 100 - residentCredentials)
            }
        }

        override val reset: ResetOps = object : ResetOps {
            override suspend fun wipeFido(): Unit = op("reset") {
                if (!resetWindowOpen) throw KeyError.ResetWindowPassed()
                touch()
                this@FakeYubiKey.pin?.fill('\u0000')
                this@FakeYubiKey.pin = null
                pinRetries = 8
                consecutiveFails = 0
                powerCycleRequired = false
                minPinLength = 4
                minPinRpIds = emptyList()
                forcePinChange = false
                templates.clear()
                residentCredentials = 0
                uvRetries = 3
                alwaysUv = spec.alwaysUv
                versions.clear()
                versions.addAll(spec.versions)
                liveTokens.forEach { it.wipe() }
                tokenEpoch++
                Unit
            }
        }

        override val attest: AttestOps = object : AttestOps {
            override suspend fun keuringCredential(token: AuthToken?): AttestationEvidence = op(if (token == null) "makeCredential:up" else "makeCredential:token") {
                if (token == null) {
                    if (alwaysUv == true || (this@FakeYubiKey.pin != null && !makeCredUvNotRqd)) throw KeyError.PinUvAuthTokenRequired()
                } else validate(token, id, Permission.MC, AttestOps.KEURING_RP_ID)
                touch()
                val rpHash = MessageDigest.getInstance("SHA-256").digest(AttestOps.KEURING_RP_ID.toByteArray())
                val flags = 0x01 or (if (token != null) 0x04 else 0) or 0x40
                val authData = rpHash + byteArrayOf(flags.toByte(), 0, 0, 0, 1) + uuidBytes(spec.aaguid)
                val leaf = if (spec.genuine) FakeAttestationJudge.GENUINE_LEAF else FakeAttestationJudge.FOREIGN_LEAF
                AttestationEvidence(
                    fmt = spec.attFmt,
                    authData = authData,
                    alg = -7,
                    sig = ByteArray(8),
                    x5c = if (spec.attFmt == "packed") listOf(leaf) else emptyList(),
                    clientDataHash = ByteArray(32),
                    rpId = AttestOps.KEURING_RP_ID,
                    withToken = token != null,
                )
            }
        }
    }

    companion object {
        val WRITE_OPS = setOf("setPin", "changePin", "setMinPinLength", "toggleAlwaysUv", "enroll", "rename", "remove", "reset")

        fun uuidBytes(a: Aaguid): ByteArray {
            val hex = a.uuid.replace("-", "")
            return ByteArray(16) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
        }
    }
}
