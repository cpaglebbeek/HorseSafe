package nl.icthorse.horsesafe.yubikey.api

import kotlinx.coroutines.flow.StateFlow

/**
 * Verbinding met precies één fysieke sleutel (A-17). Elke methode opent een EIGEN
 * `requestConnection` (kritiek 22: Management, ruwe getInfo en de CTAP-fase nooit in één verbinding),
 * draait buiten de main thread en gooit [KeyError] bij elke fout.
 *
 * Een token ([AuthToken]) uit de ene [ctap]-aanroep is in een volgende ongeldig.
 */
interface KeyLink {
    val transport: Transport

    /** false zodra de sleutel losgekoppeld is; daarna gooit elke aanroep [KeyError.Disconnected]. */
    val isConnected: StateFlow<Boolean>

    /** Management `getDeviceInfo()` in een eigen verbinding. null = Management niet beschikbaar op dit transport. */
    suspend fun readManagement(): ManagementFacts?

    /**
     * Eigen getInfo (CTAP 0x04) in een eigen verbinding: USB via `FidoProtocol.sendAndReceive(0x90, [0x04])`,
     * NFC via APDU `80 10 00 00 04`; daarna `Cbor.decode`. Leest alleen.
     */
    suspend fun readRawInfo(): RawGetInfo

    /**
     * Eén CTAP-fase: één verbinding, één `Ctap2Session`; alle stappen van [block] lopen daarbinnen.
     * Tokens die in [block] ontstaan worden na afloop gewist door de implementatie.
     */
    suspend fun <T> ctap(block: suspend CtapPhase.() -> T): T
}

/**
 * Bewerkingen binnen één CTAP-fase ([KeyLink.ctap]). Elke `*Ops` is een dunne adapter om yubikit.
 */
interface CtapPhase {
    val transport: Transport
    val pin: PinOps
    val config: ConfigOps
    val bio: BioEnrollOps
    val credMgmt: CredMgmtOps
    val attest: AttestOps
    /** Wissen (0.3.1); alleen via ResetFlow. */
    val reset: ResetOps

    /** VERSE `Ctap2Session.getInfo()` (nooit `getCachedInfo`), te gebruiken na elke schrijfactie (A-19). */
    suspend fun freshInfo(): CtapInfo
}

/**
 * Zoekt sleutels terwijl de app open is (`startUsbDiscovery`/`startNfcDiscovery`; geen USB-intent-filter,
 * kritiek 12). Meldt [KeyLinkEvent.Multiple] bij meer dan één apparaat.
 */
interface KeyDiscovery {
    val events: StateFlow<KeyLinkEvent>
    fun start(allowNfc: Boolean)
    fun stop()
}

/** Toestand van de sleuteldetectie. */
sealed class KeyLinkEvent {
    data object None : KeyLinkEvent()
    class Connected(val link: KeyLink) : KeyLinkEvent()
    data object Multiple : KeyLinkEvent()
    data object Removed : KeyLinkEvent()
}

/** Wat Management meldt. [serial] alleen voor het HMAC in [InspectorOps]; nooit tonen in een rapport. */
data class ManagementFacts(
    val firmware: Firmware?,
    val formFactor: KeyFormFactor,
    val serial: Int?,
    val pinComplexity: Boolean?,
    val enabledApplets: Map<Transport, Set<Applet>>,
) {
    override fun toString(): String = "ManagementFacts(firmware=$firmware, formFactor=$formFactor, serial=${if (serial == null) "null" else "[aanwezig]"})"
}

/** Ruwe getInfo: aanwezigheid van de sleutels die yubikit stil invult, plus hun waarden. */
data class RawGetInfo(
    val present: RawPresence,
    /** Alle CBOR-mapsleutels in de respons. */
    val keys: Set<Int>,
    val forcePinChange: Boolean?,
    val minPinLength: Int?,
    /** 0x0E als integer zoals gecodeerd door de sleutel (onzekerheid 3). */
    val firmwareVersion: Long?,
    val maxPinLength: Int?,
)

/** Verse yubikit-getInfo plus pogingen, zoals [CtapPhase.freshInfo] die teruggeeft. */
data class CtapInfo(
    val aaguid: Aaguid,
    val versions: List<String>,
    val options: Map<String, Boolean>,
    val minPinLength: Int,
    val forcePinChange: Boolean,
    val maxRpidsForSetMinPinLength: Int,
    val pinUvAuthProtocols: List<Int>,
    val uvModality: Int?,
    val pinRetries: Int?,
    val pinPowerCycleRequired: Boolean?,
    val uvRetries: Int?,
)
