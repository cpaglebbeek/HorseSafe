package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.fido.Cbor
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.KeyError
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class RawInfoTest {

    private fun hex(s: String): ByteArray = s.replace(" ", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /**
     * Vaste testbytes (met de hand gecodeerd, niet met yubikit): status 00 + map(5) met
     * 0x01 ["FIDO_2_1"], 0x0C false, 0x0D 63, 0x0E 0x050704, 0x1D 63.
     */
    private val full = hex(
        "00 a5" +
            " 01 81 68 4649444f 5f325f31" + // 1: ["FIDO_2_1"]
            " 0c f4" + //                         12: false
            " 0d 18 3f" + //                      13: 63
            " 0e 1a 00050704" + //                14: 0x050704
            " 18 1d 18 3f", //                    29: 63
    )

    @Test
    fun decodeVolledigeRespons() {
        val r = RawInfo.decodeResponse(full)
        assertTrue(r.present.forcePinChange0x0C)
        assertTrue(r.present.minPinLength0x0D)
        assertTrue(r.present.firmwareVersion0x0E)
        assertTrue(r.present.maxPinLength0x1D)
        assertEquals(false, r.forcePinChange)
        assertEquals(63, r.minPinLength)
        assertEquals(0x050704L, r.firmwareVersion)
        assertEquals(63, r.maxPinLength)
        assertEquals(setOf(0x01, 0x0C, 0x0D, 0x0E, 0x1D), r.keys)
        assertEquals(Firmware(5, 7, 4), RawInfo.decodeFirmware(r.firmwareVersion))
    }

    @Test
    fun afwezigeSleutelsBlijvenAfwezigEnWordenNietIngevuld() {
        // Alleen 0x01 en 0x04 {"clientPin": false}: geen 0x0C/0x0D/0x0E/0x1D.
        val bytes = hex("00 a2 01 81 68 4649444f5f325f31 04 a1 69 636c69656e7450696e f4")
        val r = RawInfo.decodeResponse(bytes)
        assertFalse(r.present.forcePinChange0x0C)
        assertFalse(r.present.minPinLength0x0D)
        assertFalse(r.present.firmwareVersion0x0E)
        assertFalse(r.present.maxPinLength0x1D)
        assertNull(r.maxPinLength) // yubikit zou hier stil 63 teruggeven
        assertNull(r.minPinLength) // yubikit: 4
        assertNull(r.forcePinChange)
        assertNull(RawInfo.decodeFirmware(r.firmwareVersion))
    }

    @Test
    fun statusFoutWordtKeyError() {
        try {
            RawInfo.decodeResponse(byteArrayOf(0x31))
            fail()
        } catch (e: KeyError.PinInvalid) {
        }
        try {
            RawInfo.decodeResponse(byteArrayOf(0x6A))
            fail()
        } catch (e: KeyError.Ctap) {
            assertEquals(0x6A, e.code)
        }
    }

    @Test
    fun afwijkendeVormIsProtocolfout() {
        val cases = listOf(
            ByteArray(0), //                      leeg
            byteArrayOf(0x00), //                 alleen status
            hex("00 81 01"), //                   geen map
            hex("00 a1 61 61 01"), //             tekstsleutel
            hex("00 a1 0d 61 61"), //             0x0D geen int
            hex("00 a1 0c 01"), //                0x0C geen bool
            hex("00 a1 0d"), //                   afgekapt
            hex("00 a1 0d 01 ff"), //             extra bytes
        )
        for (c in cases) {
            try {
                RawInfo.decodeResponse(c)
                fail("geen fout voor ${c.size} bytes")
            } catch (e: KeyError.Protocol) {
                assertNull(e.cause)
            }
        }
    }

    @Test
    fun firmwareDecodering() {
        assertEquals(Firmware(5, 7, 2), RawInfo.decodeFirmware(0x050702))
        assertEquals(Firmware(5, 8, 0), RawInfo.decodeFirmware(0x050800))
        assertNull(RawInfo.decodeFirmware(null))
        assertNull(RawInfo.decodeFirmware(0))
        assertNull(RawInfo.decodeFirmware(574)) // decimaal gecodeerd: niet raden
        assertNull(RawInfo.decodeFirmware(0x1000000))
    }

    @Test
    fun overUsbGaatPreciesGetInfoMetCtaphidCbor() {
        val sent = mutableListOf<ByteArray>()
        val hid = FakeHidConnection { payload -> sent += payload; full }
        val r = RawInfo.readOverFido(hid)
        assertEquals(listOf(0x86, 0x90), hid.commands) // INIT, daarna één CBOR-bericht
        assertArrayEquals(byteArrayOf(0x04), sent.single())
        assertEquals(63, r.maxPinLength)
    }

    @Test
    fun overNfcEerstSelectFidoDanNfcctapMsg() {
        val sent = mutableListOf<ByteArray>()
        val card = FakeSmartCard { payload -> sent += payload; full }
        val r = RawInfo.readOverSmartCard(card)
        assertEquals(2, card.apdus.size)
        val select = card.apdus[0]
        assertEquals(0xA4, select[1].toInt() and 0xFF)
        assertArrayEquals(hex("a0000006472f0001"), select.copyOfRange(5, 5 + select[4]))
        assertArrayEquals(hex("80 10 00 00 01 04"), card.apdus[1].copyOf(6))
        assertArrayEquals(byteArrayOf(0x04), sent.single())
        assertTrue(r.present.maxPinLength0x1D)
    }

    @Test
    fun yubikitVultAfwezigeWaardenStilIn_daaromEigenRawInfo() {
        // Documenteert het gedrag waarom RawInfo bestaat: zelfde respons zonder 0x1D.
        val withoutMax = byteArrayOf(0x00) + Cbor.encode(mapOf(1 to listOf("FIDO_2_1"), 3 to ByteArray(16)))
        val r = RawInfo.decodeResponse(withoutMax)
        assertFalse(r.present.maxPinLength0x1D)
        assertNull(r.maxPinLength)
    }
}
