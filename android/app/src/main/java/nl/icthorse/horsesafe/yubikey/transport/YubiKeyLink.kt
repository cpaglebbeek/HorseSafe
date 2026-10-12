package nl.icthorse.horsesafe.yubikey.transport

import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.ctap.Ctap2Session
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import nl.icthorse.horsesafe.yubikey.CancelSignal
import nl.icthorse.horsesafe.yubikey.MgmtOps
import nl.icthorse.horsesafe.yubikey.RawInfo
import nl.icthorse.horsesafe.yubikey.YubikitCtapPhase
import nl.icthorse.horsesafe.yubikey.keyCall
import nl.icthorse.horsesafe.yubikey.api.CtapPhase
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.ManagementFacts
import nl.icthorse.horsesafe.yubikey.api.RawGetInfo
import nl.icthorse.horsesafe.yubikey.api.Transport

/**
 * [KeyLink] op één fysieke sleutel. USB = `FidoConnection` (HID; ook voor Management), NFC =
 * `SmartCardConnection` (IsoDep). Elke methode = een eigen verbinding (kritiek 22): een token uit
 * de ene [ctap]-aanroep bestaat in de volgende niet meer.
 *
 * Na [markDisconnected] gooit elke aanroep [KeyError.Disconnected].
 */
class YubiKeyLink internal constructor(
    override val transport: Transport,
    private val runner: ConnectionRunner,
    private val onLost: (YubiKeyLink) -> Unit = {},
) : KeyLink {

    private val connected = MutableStateFlow(true)
    override val isConnected: StateFlow<Boolean> = connected.asStateFlow()

    /** Door [YubiKitKeyDiscovery] bij verwijderen of bij een tweede sleutel. */
    internal fun markDisconnected() {
        connected.value = false
    }

    private val connectionType: Class<out YubiKeyConnection> = when (transport) {
        Transport.USB -> FidoConnection::class.java
        Transport.NFC -> SmartCardConnection::class.java
    }

    private suspend fun <R> open(block: suspend (YubiKeyConnection, CancelSignal) -> R): R {
        if (!connected.value) throw KeyError.Disconnected()
        val signal = CancelSignal()
        try {
            @Suppress("UNCHECKED_CAST")
            return runner.withConnection(connectionType as Class<YubiKeyConnection>, signal) { c -> block(c, signal) }
        } catch (e: KeyError.Disconnected) {
            // Bv. NFC TagLost: de sleutel is uit het veld. Vanaf nu is deze link dood.
            markDisconnected()
            onLost(this)
            throw e
        }
    }

    override suspend fun readManagement(): ManagementFacts? = try {
        open { c, _ ->
            when (c) {
                is FidoConnection -> MgmtOps.readOverFido(c)
                is SmartCardConnection -> MgmtOps.readOverSmartCard(c)
                else -> null
            }
        }
    } catch (e: KeyError.NotSupported) {
        // Management-applet niet beschikbaar op dit transport (of uitgeschakeld): geen fout.
        null
    }

    override suspend fun readRawInfo(): RawGetInfo = open { c, _ ->
        when (c) {
            is FidoConnection -> RawInfo.readOverFido(c)
            is SmartCardConnection -> RawInfo.readOverSmartCard(c)
            else -> throw KeyError.NotSupported("verbinding")
        }
    }

    override suspend fun <T> ctap(block: suspend CtapPhase.() -> T): T = open { c, signal ->
        val disconnected = { !connected.value }
        val session: Ctap2Session = keyCall(disconnected) {
            when (c) {
                is FidoConnection -> Ctap2Session(c)
                is SmartCardConnection -> Ctap2Session(c)
                else -> throw ApplicationNotAvailableException("verbinding")
            }
        }
        val phase = YubikitCtapPhase(transport, session, disconnected, signal)
        try {
            phase.block()
        } finally {
            // Alle tokens van deze fase wissen; de verbinding sluit yubikit na de callback.
            phase.close()
        }
    }

    override fun toString(): String = "YubiKeyLink($transport, verbonden=${connected.value})"
}
