package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.fido.FidoProtocol
import com.yubico.yubikit.core.smartcard.Apdu
import com.yubico.yubikit.core.smartcard.AppId
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.core.smartcard.SmartCardProtocol
import com.yubico.yubikit.fido.Cbor
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.RawGetInfo
import nl.icthorse.horsesafe.yubikey.api.RawPresence

/**
 * Eigen authenticatorGetInfo (CTAP 0x04), buiten `Ctap2Session` om, zodat zichtbaar is welke
 * mapsleutels de sleutel ECHT stuurt. yubikit's `InfoData.fromData` vult afwezige waarden stil in
 * (0x0C → false, 0x0D → 4, 0x1D → 63), en `InfoData.getFirmwareVersion()` is package-private.
 *
 * Transport:
 * - USB: `FidoProtocol(conn).sendAndReceive(0x90 /* CTAPHID_CBOR */, [0x04], null)`;
 * - NFC: `SmartCardProtocol.select(AppId.FIDO)` en daarna APDU `80 10 00 00 01 04` (NFCCTAP_MSG).
 *
 * Alleen lezen. Draait in een eigen verbinding (kritiek 22); de aanroeper ([YubiKeyLink]) opent en
 * sluit die. Geen bestands- of netwerkcode (A-16).
 */
object RawInfo {
    /** CTAPHID_CBOR = 0x80 | 0x10 (zelfde waarde als `Ctap2Session.FidoBackend`). */
    const val CTAPHID_CBOR: Byte = 0x90.toByte()
    const val CMD_GET_INFO: Byte = 0x04

    const val KEY_FORCE_PIN_CHANGE = 0x0C
    const val KEY_MIN_PIN_LENGTH = 0x0D
    const val KEY_FIRMWARE_VERSION = 0x0E
    const val KEY_MAX_PIN_LENGTH = 0x1D

    /** NFCCTAP_MSG-APDU: CLA 0x80, INS 0x10, P1 0x00, P2 0x00, data = [getInfo]. */
    internal fun nfcGetInfoApdu(): Apdu = Apdu(0x80, 0x10, 0x00, 0x00, byteArrayOf(CMD_GET_INFO))

    /** USB/HID. De verbinding wordt NIET gesloten (dat doet yubikit na de callback). */
    fun readOverFido(connection: FidoConnection): RawGetInfo = keyCall {
        val protocol = FidoProtocol(connection)
        decodeResponse(protocol.sendAndReceive(CTAPHID_CBOR, byteArrayOf(CMD_GET_INFO), null))
    }

    /** NFC (of CCID): FIDO-applet selecteren, daarna NFCCTAP_MSG met getInfo. */
    fun readOverSmartCard(connection: SmartCardConnection): RawGetInfo = keyCall {
        val protocol = SmartCardProtocol(connection)
        protocol.select(AppId.FIDO)
        val response = protocol.sendAndReceive(nfcGetInfoApdu())
        decodeResponse(response)
    }

    /**
     * Decodeert een CTAP-antwoord: eerste byte = status, de rest = CBOR-map met integer-sleutels.
     * Status ≠ 0 → [KeyError] via [KeyErrors.fromCtap]; elke afwijking van de vorm → [KeyError.Protocol].
     */
    fun decodeResponse(response: ByteArray): RawGetInfo {
        if (response.isEmpty()) throw KeyError.Protocol("leeg-antwoord")
        val status = response[0].toInt() and 0xFF
        if (status != 0) throw KeyErrors.fromCtap(status)
        if (response.size == 1) throw KeyError.Protocol("getinfo-leeg")
        val decoded: Any? = try {
            Cbor.decode(response, 1, response.size - 1)
        } catch (t: Throwable) {
            throw KeyError.Protocol("cbor")
        }
        val map = decoded as? Map<*, *> ?: throw KeyError.Protocol("getinfo-geen-map")
        val keys = HashSet<Int>(map.size)
        for (k in map.keys) {
            keys += (k as? Int) ?: throw KeyError.Protocol("getinfo-sleutel")
        }

        fun int(key: Int): Int? = when (val v = map[key]) {
            null -> null
            is Int -> v
            else -> throw KeyError.Protocol("getinfo-0x%02x".format(key))
        }
        fun bool(key: Int): Boolean? = when (val v = map[key]) {
            null -> null
            is Boolean -> v
            else -> throw KeyError.Protocol("getinfo-0x%02x".format(key))
        }

        val presence = RawPresence(
            forcePinChange0x0C = KEY_FORCE_PIN_CHANGE in keys,
            minPinLength0x0D = KEY_MIN_PIN_LENGTH in keys,
            firmwareVersion0x0E = KEY_FIRMWARE_VERSION in keys,
            maxPinLength0x1D = KEY_MAX_PIN_LENGTH in keys,
        )
        return RawGetInfo(
            present = presence,
            keys = keys,
            forcePinChange = bool(KEY_FORCE_PIN_CHANGE),
            minPinLength = int(KEY_MIN_PIN_LENGTH),
            firmwareVersion = int(KEY_FIRMWARE_VERSION)?.toLong(),
            maxPinLength = int(KEY_MAX_PIN_LENGTH),
        )
    }

    /**
     * 0x0E naar [Firmware]. Aanname (onzekerheid 3, nog te meten op de testsleutel): Yubico codeert
     * `major << 16 | minor << 8 | patch`, bv. 0x050704 = 5.7.4. Valt de waarde buiten dat patroon
     * (major 0 of > 0x20, of > 24 bits), dan `null` = niet te bepalen; nooit gokken.
     */
    fun decodeFirmware(value: Long?): Firmware? {
        if (value == null || value < 0x010000L || value > 0xFFFFFFL) return null
        val major = ((value shr 16) and 0xFF).toInt()
        val minor = ((value shr 8) and 0xFF).toInt()
        val patch = (value and 0xFF).toInt()
        if (major !in 1..0x20) return null
        return Firmware(major, minor, patch)
    }
}
