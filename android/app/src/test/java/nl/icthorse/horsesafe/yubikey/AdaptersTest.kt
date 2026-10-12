package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.Transport as YkTransport
import com.yubico.yubikit.core.Version
import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.management.Capability
import com.yubico.yubikit.management.DeviceConfig
import com.yubico.yubikit.management.DeviceInfo
import com.yubico.yubikit.management.FormFactor
import java.io.IOException
import kotlin.coroutines.cancellation.CancellationException
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.Applet
import nl.icthorse.horsesafe.yubikey.api.CtapInfo
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.FirmwareSource
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyFormFactor
import nl.icthorse.horsesafe.yubikey.api.KeyVariant
import nl.icthorse.horsesafe.yubikey.api.ManagementFacts
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.RawGetInfo
import nl.icthorse.horsesafe.yubikey.api.RawPresence
import nl.icthorse.horsesafe.yubikey.api.Transport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AdaptersTest {

    // ---- KeyErrors ----

    @Test
    fun ctapCodesNaarKeyError() {
        val expect = mapOf(
            0x31 to KeyError.PinInvalid::class, 0x32 to KeyError.PinBlocked::class,
            0x34 to KeyError.PinAuthBlocked::class, 0x35 to KeyError.PinNotSet::class,
            0x36 to KeyError.PinUvAuthTokenRequired::class, 0x37 to KeyError.PinPolicyViolation::class,
            0x3F to KeyError.UvInvalid::class, 0x3C to KeyError.UvBlocked::class,
            0x27 to KeyError.OperationDenied::class, 0x30 to KeyError.OperationDenied::class,
            0x33 to KeyError.TokenInvalid::class, 0x38 to KeyError.TokenInvalid::class, 0x40 to KeyError.TokenInvalid::class,
            0x2F to KeyError.UserActionTimeout::class, 0x2D to KeyError.UserActionTimeout::class,
            0x01 to KeyError.NotSupported::class, 0x6A to KeyError.Ctap::class,
        )
        for ((code, type) in expect) {
            val e = KeyErrors.map(CtapException(code.toByte()))
            assertEquals("0x%02x".format(code), type, e::class)
            assertNull(e.cause)
        }
    }

    @Test
    fun ioEnOverigeFoutenZonderOorzaakOfBericht() {
        val secretLooking = "a1b2c3d4e5f6 PIN=geheim"
        val io = KeyErrors.map(IOException(secretLooking))
        assertTrue(io is KeyError.Io)
        assertFalse(io.message!!.contains("geheim"))
        assertNull(io.cause)
        assertTrue(KeyErrors.map(IOException(secretLooking), disconnected = true) is KeyError.Disconnected)
        assertTrue(KeyErrors.map(ApplicationNotAvailableException(secretLooking)) is KeyError.NotSupported)
        val ise = KeyErrors.map(IllegalStateException(secretLooking))
        assertTrue(ise is KeyError.Protocol)
        assertFalse(ise.message!!.contains("geheim"))
        val c = CancellationException("x")
        assertSame(c, KeyErrors.map(c))
        val k = KeyError.Cancelled()
        assertSame(k, KeyErrors.map(k))
    }

    // ---- Tokens ----

    @Test
    fun permissieBitsGelijkAanYubikit() {
        for (p in Permission.entries) assertEquals(Tokens.YUBIKIT_BITS[p], Tokens.bitsFor(p))
        assertEquals(4, Tokens.YUBIKIT_BITS.size)
    }

    @Test
    fun phaseTokenWistEnVerbergt() {
        val bytes = ByteArray(32) { 0x5A }
        val t = PhaseToken(Permission.BE, null, bytes, Any())
        assertFalse(t.toString().contains("5a", ignoreCase = true))
        t.close()
        assertTrue(t.isWiped)
        assertTrue(bytes.all { it.toInt() == 0 })
        try {
            t.raw(); fail()
        } catch (e: KeyError.TokenInvalid) {
        }
    }

    // ---- Management ----

    @Test
    fun managementNaarFacts() {
        val info = DeviceInfo.Builder()
            .version(Version(5, 7, 4))
            .formFactor(FormFactor.USB_C_BIO)
            .serialNumber(12345678)
            .pinComplexity(true)
            .supportedCapabilities(mapOf(YkTransport.USB to (Capability.FIDO2.bit or Capability.U2F.bit or Capability.PIV.bit)))
            .config(DeviceConfig.Builder().enabledCapabilities(YkTransport.USB, Capability.FIDO2.bit or Capability.U2F.bit).build())
            .build()
        val f = MgmtOps.toFacts(info)
        assertEquals(Firmware(5, 7, 4), f.firmware)
        assertEquals(KeyFormFactor.USB_C_BIO, f.formFactor)
        assertEquals(12345678, f.serial)
        assertEquals(true, f.pinComplexity)
        assertEquals(mapOf(Transport.USB to setOf(Applet.FIDO2, Applet.U2F)), f.enabledApplets)
        assertFalse(f.toString().contains("12345678"))
        assertNull(MgmtOps.toFacts(DeviceInfo.Builder().build()).firmware) // 0.0.0 = onbekend
    }

    // ---- Inspector ----

    private val aaguid = Aaguid("9dd8d593-2213-438a-97f8-d6b813d51c27")
    private val lookup = AaguidLookup { if (it == aaguid) AaguidEntry(KeyClass.BIO, KeyVariant.FIDO, "YubiKey Bio") else null }
    private val hasher = SerialHmac(ByteArray(32) { it.toByte() })

    private fun info(a: Aaguid = aaguid) = CtapInfo(
        aaguid = a, versions = listOf("FIDO_2_1"), options = mapOf("clientPin" to false, "alwaysUv" to true),
        minPinLength = 4, forcePinChange = false, maxRpidsForSetMinPinLength = 1, pinUvAuthProtocols = listOf(2, 1),
        uvModality = 2, pinRetries = 8, pinPowerCycleRequired = null, uvRetries = 3,
    )

    private fun raw(maxPresent: Boolean, fw: Long? = null) = RawGetInfo(
        present = RawPresence(false, false, fw != null, maxPresent),
        keys = setOf(1, 3, 4),
        forcePinChange = null, minPinLength = null, firmwareVersion = fw,
        maxPinLength = if (maxPresent) 63 else null,
    )

    private val mgmt = ManagementFacts(Firmware(5, 7, 4), KeyFormFactor.USB_C_BIO, 42, false, emptyMap())

    @Test
    fun inspectorCombineert() {
        val f = Inspector(lookup, hasher).combine(Transport.USB, mgmt, raw(maxPresent = false), info())
        assertEquals(KeyClass.BIO, f.keyClass)
        assertEquals(KeyVariant.FIDO, f.variant)
        assertNull(f.maxPinLength) // afwezig = onbekend, nooit yubikit's stille 63
        assertFalse(f.rawPresent.maxPinLength0x1D)
        assertEquals(FirmwareSource.MANAGEMENT, f.firmwareSource)
        assertEquals(hasher.hmacHex(42), f.serialHmac)
        assertEquals(64, f.serialHmac!!.length)
        assertFalse(f.toString().contains("serial=42"))
        assertEquals(63, Inspector(lookup, hasher).combine(Transport.USB, mgmt, raw(true), info()).maxPinLength)
    }

    @Test
    fun firmwareBronVolgorde() {
        val ins = Inspector(lookup, null)
        assertEquals(Firmware(5, 7, 2) to FirmwareSource.RAW_GETINFO, ins.firmwareOf(null, raw(false, 0x050702)))
        assertEquals(null to FirmwareSource.NONE, ins.firmwareOf(null, raw(false)))
        assertEquals(Firmware(5, 7, 4) to FirmwareSource.MANAGEMENT, ins.firmwareOf(mgmt, raw(false, 0x050702)))
        val f = ins.combine(Transport.NFC, null, raw(false), info(Aaguid("00000000-0000-0000-0000-000000000000")))
        assertEquals(KeyClass.UNKNOWN, f.keyClass)
        assertNull(f.serialHmac)
        assertNull(f.enabledApplets)
    }

    @Test
    fun serialHmacIsSleutelafhankelijk() {
        val other = SerialHmac(ByteArray(32) { 1 })
        assertNotEquals(hasher.hmacHex(42), other.hmacHex(42))
        assertNotEquals(hasher.hmacHex(42), hasher.hmacHex(43))
        assertEquals(hasher.hmacHex(42), hasher.hmacHex(42))
        assertFalse(hasher.toString().contains("00"))
    }

    @Test
    fun vingernamen() {
        assertTrue(FingerName.isValid("R-wijs", 15))
        assertFalse(FingerName.isValid("R-wijsvinger-lang", 15))
        assertFalse(FingerName.isValid("dúim", 15))
        assertFalse(FingerName.isValid(" R", 15))
        assertFalse(FingerName.isValid("", 15))
    }
}
