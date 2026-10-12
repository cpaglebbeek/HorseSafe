package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.management.FormFactor
import com.yubico.yubikit.management.ManagementSession
import nl.icthorse.horsesafe.yubikey.api.Applet
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.KeyFormFactor
import nl.icthorse.horsesafe.yubikey.api.ManagementFacts
import nl.icthorse.horsesafe.yubikey.api.Transport
import com.yubico.yubikit.core.Transport as YkTransport

/**
 * Management-applet, ALLEEN LEZEN: `ManagementSession.getDeviceInfo()`. Nooit `updateDeviceConfig`,
 * `setMode` of `deviceReset` (A-18; applets alleen tonen, open vraag 7).
 *
 * USB via `FidoConnection` (werkt ook op de HID-only Bio; eigen CTAPHID_INIT, kritiek 22),
 * NFC via `SmartCardConnection` (Management-AID).
 */
object MgmtOps {

    fun readOverFido(connection: FidoConnection): ManagementFacts = keyCall {
        toFacts(ManagementSession(connection).deviceInfo)
    }

    fun readOverSmartCard(connection: SmartCardConnection): ManagementFacts = keyCall {
        toFacts(ManagementSession(connection).deviceInfo)
    }

    /** Pure omzetting, los testbaar met `DeviceInfo.Builder`. */
    fun toFacts(info: DeviceInfo): ManagementFacts {
        val v = info.version
        val firmware = if (v.major.toInt() == 0 && v.minor.toInt() == 0 && v.micro.toInt() == 0) {
            null
        } else {
            Firmware(v.major.toInt() and 0xFF, v.minor.toInt() and 0xFF, v.micro.toInt() and 0xFF)
        }
        val applets = buildMap {
            for ((yk, ours) in listOf(YkTransport.USB to Transport.USB, YkTransport.NFC to Transport.NFC)) {
                if (!info.hasTransport(yk)) continue
                val enabled = info.config.getEnabledCapabilities(yk) ?: continue
                put(ours, appletsOf(enabled))
            }
        }
        return ManagementFacts(
            firmware = firmware,
            formFactor = formFactorOf(info.formFactor),
            serial = info.serialNumber,
            pinComplexity = info.pinComplexity,
            enabledApplets = applets,
        )
    }

    fun appletsOf(bits: Int): Set<Applet> = buildSet {
        if (bits and Capability.OTP.bit != 0) add(Applet.OTP)
        if (bits and Capability.U2F.bit != 0) add(Applet.U2F)
        if (bits and Capability.FIDO2.bit != 0) add(Applet.FIDO2)
        if (bits and Capability.OATH.bit != 0) add(Applet.OATH)
        if (bits and Capability.PIV.bit != 0) add(Applet.PIV)
        if (bits and Capability.OPENPGP.bit != 0) add(Applet.OPENPGP)
        if (bits and Capability.HSMAUTH.bit != 0) add(Applet.HSMAUTH)
    }

    fun formFactorOf(ff: FormFactor): KeyFormFactor = when (ff) {
        FormFactor.USB_A_KEYCHAIN -> KeyFormFactor.USB_A_KEYCHAIN
        FormFactor.USB_A_NANO -> KeyFormFactor.USB_A_NANO
        FormFactor.USB_C_KEYCHAIN -> KeyFormFactor.USB_C_KEYCHAIN
        FormFactor.USB_C_NANO -> KeyFormFactor.USB_C_NANO
        FormFactor.USB_C_LIGHTNING -> KeyFormFactor.USB_C_LIGHTNING
        FormFactor.USB_A_BIO -> KeyFormFactor.USB_A_BIO
        FormFactor.USB_C_BIO -> KeyFormFactor.USB_C_BIO
        else -> KeyFormFactor.UNKNOWN
    }
}
