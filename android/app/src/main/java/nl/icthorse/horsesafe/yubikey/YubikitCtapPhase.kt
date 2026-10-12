package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol
import java.util.Locale
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.BioEnrollOps
import nl.icthorse.horsesafe.yubikey.api.ConfigOps
import nl.icthorse.horsesafe.yubikey.api.CredMgmtOps
import nl.icthorse.horsesafe.yubikey.api.CtapInfo
import nl.icthorse.horsesafe.yubikey.api.CtapPhase
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.PinOps
import nl.icthorse.horsesafe.yubikey.api.Transport

/**
 * Annuleersignaal tussen de aanroepende coroutine en de blokkerende yubikit-aanroep op de
 * verbindingsthread. [fire] zet de lopende `CommandState` op geannuleerd; yubikit stuurt dan
 * CTAPHID_CANCEL (USB) of P1=0x11 (NFC) en de sleutel antwoordt KEEPALIVE_CANCEL.
 */
class CancelSignal {
    @Volatile
    var isFired: Boolean = false
        private set

    @Volatile
    private var hook: (() -> Unit)? = null

    internal fun setHook(h: (() -> Unit)?) {
        hook = h
        if (isFired) h?.invoke()
    }

    fun fire() {
        isFired = true
        hook?.invoke()
    }
}

/**
 * Eén CTAP-fase: één verbinding, één [Ctap2Session] (kritiek 22). Alle `*Ops` delen deze context.
 *
 * - Bij het openen wordt meteen een VERSE getInfo gedaan; [info] is altijd de laatste verse getInfo
 *   en wordt na elke schrijfactie ververst door [refresh]. Eigen code roept nooit
 *   de gecachete getInfo van `Ctap2Session` aan (kritiek 18). yubikit zelf gebruikt intern zijn cache voor
 *   `isSupported`-controles; daarom controleren de adapters de ondersteuning vooraf op [info].
 * - PinUvAuthProtocol: V2 als de sleutel 2 meldt, anders V1; vast voor de hele fase, zodat een token
 *   altijd bij zijn protocol hoort.
 * - [close] wist alle tokens die in deze fase zijn uitgegeven.
 */
internal class YubikitCtapPhase(
    override val transport: Transport,
    internal val session: Ctap2Session,
    private val disconnected: () -> Boolean = { false },
    cancel: CancelSignal? = null,
) : CtapPhase, AutoCloseable {

    @Volatile
    private var closed = false

    private val tokens = mutableListOf<PhaseToken>()

    /** Laatste VERSE getInfo; de eerste wordt hier, bij het openen van de fase, opgehaald. */
    @Volatile
    internal var info: Ctap2Session.InfoData = call { session.getInfo() }
        private set

    @Volatile
    private var activeState: CommandState? = null

    private var protocolCache: PinUvAuthProtocol? = null

    init {
        cancel?.setHook { activeState?.cancel() }
    }

    override val pin: PinOps = YubikitPinOps(this)
    override val config: ConfigOps = YubikitConfigOps(this)
    override val bio: BioEnrollOps = YubikitBioEnrollOps(this)
    override val credMgmt: CredMgmtOps = YubikitCredMgmtOps(this)
    override val attest: AttestOps = YubikitAttestOps(this)

    /** Protocol voor deze fase (eerste keer gekozen op de verse getInfo). */
    internal val protocol: PinUvAuthProtocol
        @Synchronized get() = protocolCache ?: Tokens.selectProtocol(info.pinUvAuthProtocols).also { protocolCache = it }

    internal fun clientPin(): ClientPin = ClientPin(session, protocol)

    /** Verse getInfo (nooit de cache) en bewaar die als [info]. */
    internal fun refresh(): Ctap2Session.InfoData = call { session.getInfo() }.also { info = it }

    internal fun option(name: String): Boolean? = info.options[name] as? Boolean

    internal fun hasOption(name: String): Boolean = info.options.containsKey(name)

    internal fun tokenSupported(): Boolean = ClientPin.isTokenSupported(info)

    /** Zet een nieuw token op de lijst van deze fase. */
    @Synchronized
    internal fun register(permission: Permission, rpId: String?, bytes: ByteArray): AuthToken {
        if (closed) {
            bytes.fill(0)
            throw KeyError.TokenInvalid()
        }
        return PhaseToken(permission, rpId, bytes, this).also { tokens += it }
    }

    /**
     * Ruwe bytes van een token uit DEZE fase met precies [required] als permissie (en bij MC de
     * keurings-rpId). Anders [KeyError.TokenInvalid].
     */
    internal fun unwrap(token: AuthToken, required: Permission): ByteArray {
        if (closed) throw KeyError.TokenInvalid()
        val t = token as? PhaseToken ?: throw KeyError.TokenInvalid()
        if (t.owner !== this || t.permission != required || t.isWiped) throw KeyError.TokenInvalid()
        if (required == Permission.MC && t.rpId != AttestOps.KEURING_RP_ID) throw KeyError.TokenInvalid()
        return t.raw()
    }

    /** Nieuwe CommandState die via [CancelSignal] te annuleren is; na gebruik [endCommand]. */
    internal fun beginCommand(): CommandState = CommandState().also { activeState = it }

    internal fun endCommand(state: CommandState) {
        if (activeState === state) activeState = null
    }

    /** yubikit-aanroep met foutvertaling; gooit [KeyError.TokenInvalid] na [close]. */
    internal fun <T> call(block: () -> T): T {
        if (closed) throw KeyError.TokenInvalid()
        return keyCall(disconnected, block)
    }

    override suspend fun freshInfo(): CtapInfo {
        val i = refresh()
        val aaguidBytes = i.aaguid ?: throw KeyError.Protocol("aaguid")
        val options = buildMap {
            for ((k, v) in i.options) if (v is Boolean) put(k, v)
        }
        val hasClientPin = options.containsKey("clientPin")
        val pinRetries = if (hasClientPin && i.pinUvAuthProtocols.isNotEmpty()) {
            optionalCtap { clientPin().pinRetries }
        } else {
            null
        }
        val uvRetries = if (options.containsKey("uv") && i.pinUvAuthProtocols.isNotEmpty()) {
            optionalCtap { clientPin().uvRetries }
        } else {
            null
        }
        return CtapInfo(
            aaguid = aaguidOf(aaguidBytes),
            versions = i.versions.toList(),
            options = options,
            minPinLength = i.minPinLength,
            forcePinChange = i.forcePinChange,
            maxRpidsForSetMinPinLength = i.maxRpidsForSetMinPinLength,
            pinUvAuthProtocols = i.pinUvAuthProtocols.toList(),
            uvModality = if (i.uvModality == 0) null else i.uvModality,
            pinRetries = pinRetries?.count,
            pinPowerCycleRequired = pinRetries?.powerCycleState,
            uvRetries = uvRetries,
        )
    }

    /** Lees iets optioneels; een CTAP-weigering geeft null, een verbindingsfout gaat door. */
    internal fun <T> optionalCtap(block: () -> T): T? = try {
        call {
            try {
                block()
            } catch (e: CtapException) {
                null
            }
        }
    } catch (e: KeyError.Protocol) {
        null
    }

    @Synchronized
    override fun close() {
        closed = true
        activeState?.cancel()
        tokens.forEach { it.wipe() }
        tokens.clear()
    }

    companion object {
        fun aaguidOf(bytes: ByteArray): Aaguid {
            if (bytes.size != 16) throw KeyError.Protocol("aaguid-lengte")
            val hex = bytes.joinToString("") { "%02x".format(Locale.ROOT, it) }
            return Aaguid("${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}")
        }
    }
}
