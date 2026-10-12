package nl.icthorse.horsesafe.yubikey.transport

import android.app.Activity
import android.content.Context
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import nl.icthorse.horsesafe.yubikey.api.KeyDiscovery
import nl.icthorse.horsesafe.yubikey.api.KeyLinkEvent
import nl.icthorse.horsesafe.yubikey.api.Transport

/**
 * Sleuteldetectie via `YubiKitManager`, ALLEEN terwijl de app open is (kritiek 12): de app-laag roept
 * [start] in `onStart`/`onResume` en [stop] in `onPause`/`onStop`. Er is geen USB-intent-filter en
 * geen device_filter.xml; yubikit vraagt de USB-permissie zelf (`handlePermissions(true)`, filter op
 * VID 0x1050).
 *
 * Precies één sleutel (A-17, F1.1):
 * - één aangesloten sleutel → [KeyLinkEvent.Connected];
 * - een tweede (USB of NFC naast USB) → [KeyLinkEvent.Multiple]; alle links worden ongeldig, en pas
 *   als ALLES weer los is ([KeyLinkEvent.Removed]) telt een nieuwe sleutel weer;
 * - USB los → [KeyLinkEvent.Removed] (via `UsbYubiKeyDevice.setOnClosed`).
 *
 * NFC: een tag heeft geen los-melding. Een NFC-link is geldig tot een verbinding faalt met
 * TagLost ([YubiKeyLink] meldt dat via `onLost`) of tot een nieuwe NFC-tap; die vervangt de vorige
 * link (opnieuw tikken is normaal bij NFC). Of het dezelfde sleutel is, controleert de flow
 * (AAGUID/serialHmac, Stop.KEY_SWAPPED).
 *
 * @param activity levert de actieve Activity voor NFC-foreground-dispatch; null = geen NFC.
 * @param nfcTimeoutMs IsoDep-time-out (open vraag 6: 5000 ms voor setPin/config/makeCredential).
 */
class YubiKitKeyDiscovery(
    context: Context,
    private val activity: () -> Activity?,
    private val nfcTimeoutMs: Int = 5000,
) : KeyDiscovery {

    private val manager = YubiKitManager(context.applicationContext)
    private val state = MutableStateFlow<KeyLinkEvent>(KeyLinkEvent.None)
    override val events: StateFlow<KeyLinkEvent> = state.asStateFlow()

    private val lock = Any()
    private val usb = LinkedHashMap<UsbYubiKeyDevice, YubiKeyLink>()
    @Volatile
    private var nfc: YubiKeyLink? = null
    private var multiple = false
    private var started = false
    private var nfcActivity: Activity? = null

    override fun start(allowNfc: Boolean) {
        synchronized(lock) {
            if (started) return
            started = true
        }
        manager.startUsbDiscovery(UsbConfiguration().handlePermissions(true)) { device -> onUsbAttached(device) }
        if (allowNfc) {
            val act = activity()
            if (act != null) {
                try {
                    manager.startNfcDiscovery(NfcConfiguration().timeout(nfcTimeoutMs), act) { device -> onNfc(device) }
                    synchronized(lock) { nfcActivity = act }
                } catch (e: NfcNotAvailable) {
                    // Geen NFC of uitgeschakeld: alleen USB.
                }
            }
        }
    }

    override fun stop() {
        val act: Activity?
        synchronized(lock) {
            if (!started) return
            started = false
            act = nfcActivity
            nfcActivity = null
        }
        manager.stopUsbDiscovery()
        if (act != null) manager.stopNfcDiscovery(act)
        synchronized(lock) {
            usb.values.forEach { it.markDisconnected() }
            usb.clear()
            nfc?.markDisconnected()
            nfc = null
            multiple = false
            state.value = KeyLinkEvent.None
        }
    }

    private fun onUsbAttached(device: UsbYubiKeyDevice) {
        val link = YubiKeyLink(Transport.USB, DeviceConnectionRunner(device) { !isCurrent(device) }) { lost -> onLinkLost(lost) }
        synchronized(lock) {
            if (!started) return
            usb[device] = link
            publish()
        }
        device.setOnClosed { onUsbRemoved(device) }
    }

    private fun onUsbRemoved(device: UsbYubiKeyDevice) {
        synchronized(lock) {
            usb.remove(device)?.markDisconnected()
            publishAfterRemoval()
        }
    }

    private fun onNfc(device: NfcYubiKeyDevice) {
        lateinit var link: YubiKeyLink
        link = YubiKeyLink(Transport.NFC, DeviceConnectionRunner(device) { nfc !== link }) { lost -> onLinkLost(lost) }
        synchronized(lock) {
            if (!started) return
            nfc?.markDisconnected()
            nfc = link
            publish()
        }
    }

    private fun onLinkLost(link: YubiKeyLink) {
        synchronized(lock) {
            if (nfc === link) nfc = null
            val usbEntry = usb.entries.firstOrNull { it.value === link }
            if (usbEntry != null) usb.remove(usbEntry.key)
            publishAfterRemoval()
        }
    }

    private fun isCurrent(device: UsbYubiKeyDevice): Boolean = synchronized(lock) { usb.containsKey(device) && !multiple }

    /** Onder [lock]. */
    private fun count(): Int = usb.size + (if (nfc != null) 1 else 0)

    /** Onder [lock]. */
    private fun publish() {
        val n = count()
        if (n > 1 || multiple) {
            multiple = true
            usb.values.forEach { it.markDisconnected() }
            nfc?.markDisconnected()
            state.value = KeyLinkEvent.Multiple
        } else if (n == 1) {
            val only = usb.values.firstOrNull() ?: nfc!!
            state.value = KeyLinkEvent.Connected(only)
        }
    }

    /** Onder [lock]. */
    private fun publishAfterRemoval() {
        if (count() == 0) {
            multiple = false
            state.value = KeyLinkEvent.Removed
        } else if (multiple) {
            state.value = KeyLinkEvent.Multiple
        }
    }
}
