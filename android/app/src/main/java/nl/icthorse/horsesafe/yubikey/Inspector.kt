package nl.icthorse.horsesafe.yubikey

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.CtapInfo
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.FirmwareSource
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyFormFactor
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.KeyVariant
import nl.icthorse.horsesafe.yubikey.api.ManagementFacts
import nl.icthorse.horsesafe.yubikey.api.RawGetInfo

/** Wat de allowlist (assets/trust/aaguids.json) over een AAGUID weet. */
data class AaguidEntry(val keyClass: KeyClass, val variant: KeyVariant, val description: String?)

/**
 * Opzoeken in de AAGUID-allowlist. De app-laag levert de implementatie (bijv. een adapter om
 * `attest/AaguidAllowlist`), zodat in `yubikey/` geen bestandscode staat (A-16). null = niet in de
 * allowlist → [KeyClass.UNKNOWN] (altijd STOP).
 */
fun interface AaguidLookup {
    fun lookup(aaguid: Aaguid): AaguidEntry?
}

/** HMAC van het serienummer (kritiek 8); het ruwe nummer verlaat de yubikey-laag niet. */
fun interface SerialHasher {
    fun hmacHex(serial: Int): String
}

/**
 * HMAC-SHA256(app-privé random sleutel, serienummer als 4 bytes big-endian), als kleine-letter-hex.
 * De sleutel (≥ 32 bytes) maakt de app-laag één keer aan met SecureRandom en bewaart hem app-privé;
 * deze klasse leest of schrijft zelf niets (A-16). [toString] toont de sleutel niet.
 */
class SerialHmac(key: ByteArray) : SerialHasher {
    private val key: ByteArray = key.copyOf()

    init {
        require(this.key.size >= 32) { "HMAC-sleutel te kort" }
    }

    override fun hmacHex(serial: Int): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val input = byteArrayOf((serial ushr 24).toByte(), (serial ushr 16).toByte(), (serial ushr 8).toByte(), serial.toByte())
        return mac.doFinal(input).joinToString("") { "%02x".format(it) }
    }

    override fun toString(): String = "SerialHmac([verborgen])"
}

/**
 * F1 Herkennen, alleen lezen. Drie aparte verbindingen (kritiek 22), in deze volgorde:
 * 1. Management (`getDeviceInfo`): firmware, vormfactor, serienummer → alleen [SerialHasher], applets,
 *    PIN-complexiteit. Niet beschikbaar of mislukt → doorgaan zonder (behalve bij losgekoppeld).
 * 2. Ruwe getInfo ([RawInfo]): aanwezigheid van 0x0C/0x0D/0x0E/0x1D en de echte maxPINLength.
 * 3. CTAP-fase met een VERSE getInfo + PIN-/UV-pogingen ([CtapPhase.freshInfo]); nooit de cache.
 *
 * Firmware: Management, anders ruwe 0x0E, anders onbekend ([FirmwareSource.NONE]). Een
 * AAGUID-tabel als derde bron is nog niet mogelijk: aaguids.json bevat (nog) geen firmware en het
 * contract [FirmwareSource] kent die bron niet (zie notes).
 */
class Inspector(
    private val aaguids: AaguidLookup,
    private val serialHasher: SerialHasher?,
) : InspectorOps {

    override suspend fun inspect(link: KeyLink): KeyFacts {
        val mgmt: ManagementFacts? = try {
            link.readManagement()
        } catch (e: KeyError.Disconnected) {
            throw e
        } catch (e: KeyError.MultipleKeys) {
            throw e
        } catch (e: KeyError) {
            null
        }
        val raw = link.readRawInfo()
        val info = link.ctap { freshInfo() }
        return combine(link.transport, mgmt, raw, info)
    }

    /** Pure samenvoeging, los testbaar. */
    internal fun combine(
        transport: nl.icthorse.horsesafe.yubikey.api.Transport,
        mgmt: ManagementFacts?,
        raw: RawGetInfo,
        info: CtapInfo,
    ): KeyFacts {
        val entry = aaguids.lookup(info.aaguid)
        val (firmware, source) = firmwareOf(mgmt, raw)
        return KeyFacts(
            transport = transport,
            aaguid = info.aaguid,
            keyClass = entry?.keyClass ?: KeyClass.UNKNOWN,
            variant = entry?.variant ?: KeyVariant.UNKNOWN,
            aaguidDescription = entry?.description,
            firmware = firmware,
            firmwareSource = source,
            formFactor = mgmt?.formFactor ?: KeyFormFactor.UNKNOWN,
            serialHmac = mgmt?.serial?.let { s -> serialHasher?.hmacHex(s) },
            versions = info.versions,
            options = info.options,
            rawPresent = raw.present,
            // 0x0D uit de ruwe respons als die er is (yubikit vult anders stil 4 in).
            minPinLength = raw.minPinLength ?: info.minPinLength,
            // 0x1D: alleen de ruwe waarde telt; afwezig = onbekend (yubikit zou stil 63 geven).
            maxPinLength = if (raw.present.maxPinLength0x1D) raw.maxPinLength else null,
            forcePinChange = raw.forcePinChange ?: info.forcePinChange,
            pinRetries = info.pinRetries,
            pinPowerCycleRequired = info.pinPowerCycleRequired,
            uvRetries = info.uvRetries,
            maxRpidsForSetMinPinLength = info.maxRpidsForSetMinPinLength,
            pinUvAuthProtocols = info.pinUvAuthProtocols,
            pinComplexity = mgmt?.pinComplexity,
            enabledApplets = mgmt?.enabledApplets,
        )
    }

    internal fun firmwareOf(mgmt: ManagementFacts?, raw: RawGetInfo): Pair<Firmware?, FirmwareSource> {
        mgmt?.firmware?.let { return it to FirmwareSource.MANAGEMENT }
        RawInfo.decodeFirmware(raw.firmwareVersion)?.let { return it to FirmwareSource.RAW_GETINFO }
        return null to FirmwareSource.NONE
    }
}
