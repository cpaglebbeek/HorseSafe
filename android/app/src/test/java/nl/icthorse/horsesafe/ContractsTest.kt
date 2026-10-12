package nl.icthorse.horsesafe

import nl.icthorse.horsesafe.flow.AttestTiming
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.ConfigOps
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.TemplateId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Bewaakt de vaste waarden in de contracten (fundamentfase). */
class ContractsTest {
    @Test fun firmwareGrenzenPerKlasse() {
        assertEquals(Firmware(5, 7, 2), KeyClass.BIO.minFirmware)
        assertEquals(Firmware(5, 7, 0), KeyClass.YUBIKEY5.minFirmware)
        assertTrue(Firmware(5, 7, 1) < KeyClass.BIO.minFirmware!!)
        assertTrue(Firmware(5, 7, 0) >= KeyClass.YUBIKEY5.minFirmware!!)
        assertTrue(Firmware(5, 6, 9) < Firmware(5, 7, 0))
    }

    @Test fun attestMoment() {
        assertEquals(AttestTiming.BEFORE_SET_PIN, Profile.RECOVERY_YK5.attestTiming(alwaysUv = true))
        assertEquals(AttestTiming.BEFORE_SET_PIN, Profile.BIO_MAIN.attestTiming(alwaysUv = false))
        assertEquals(AttestTiming.AFTER_SET_PIN, Profile.BIO_MAIN.attestTiming(alwaysUv = true))
        assertEquals(AttestTiming.AFTER_SET_PIN, Profile.RECOVERY_BIO.attestTiming(alwaysUv = true))
    }

    @Test fun vasteWaarden() {
        assertEquals("[verborgen]", SecretBuffer.HIDDEN)
        assertEquals(63, SecretBuffer.PIN_LENGTH)
        assertEquals(63, ConfigOps.MIN_PIN_LENGTH)
        assertEquals("keuring.horsesafe.invalid", AttestOps.KEURING_RP_ID)
        assertEquals(listOf(0x01, 0x04, 0x08, 0x20), Permission.entries.map { it.bit })
    }

    @Test fun stopsHebbenTekstEnAdvies() {
        Stop.entries.forEach {
            assertTrue(it.name, it.tekst.isNotBlank() && it.advies.isNotBlank())
        }
    }

    @Test fun stoppedIsLaatsteOrder() {
        assertTrue(State.Done.order < State.Stopped(Stop.INTERNAL_ERROR, emptySet(), 0).order)
    }

    @Test fun templateIdVergelijktInhoud() {
        assertEquals(TemplateId(byteArrayOf(1, 2)), TemplateId(byteArrayOf(1, 2)))
    }
}
