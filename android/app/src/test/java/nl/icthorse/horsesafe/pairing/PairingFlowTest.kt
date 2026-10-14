package nl.icthorse.horsesafe.pairing

import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.keystore.KeySlot
import nl.icthorse.horsesafe.net.HttpResponse
import nl.icthorse.horsesafe.net.DeviceApi
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Koppelflow end-to-end op de JVM met nep-sleutels (software-EC/AES), een nep-vinger en een nep-server die
 * de controles uit §13.5 (mac_srv, sig_biosig) en de SAS zelf narekent. Geen netwerk, geen productie.
 */
class PairingFlowTest {
    private val pairingId = PairFixture.PAIRING_ID
    private val deviceId = PairFixture.DEVICE_ID
    private val keyId = PairFixture.KEY_ID

    private fun qr() = PairingQr.parse(PairFixture.qrText())!!

    private class Setup(val dir: File, val keys: FakeKeys, val finger: FakeFinger, val server: FakeServer, val flow: PairingFlow)

    private fun setup(
        finger: FakeFinger = FakeFinger(),
        clock: () -> Long = { System.currentTimeMillis() },
        transport: ((FakeServer) -> nl.icthorse.horsesafe.net.HttpTransport)? = null,
        tweak: (FakeServer) -> Unit = {},
    ): Setup {
        val dir = Files.createTempDirectory("hs-pair").toFile()
        val keys = FakeKeys()
        val server = FakeServer(keys).also(tweak)
        val flow = PairingFlow(keys, finger, DeviceApi(transport?.invoke(server) ?: server), DeviceStore(dir), clockMillis = clock)
        return Setup(dir, keys, finger, server, flow)
    }

    private val info = DeviceInfo("Galaxy Z Fold6", "SM-F956B", "0.3.4-Miller")

    @Test fun happyPath() = runTest {
        val x = setup()
        try {
            val q = qr()
            val rec = x.flow.claim(q, info)
            assertTrue("QR-geheim gewist", q.secret.all { it == 0.toByte() })
            assertEquals(listOf(FingerStep.WRAP, FingerStep.SIGN), x.finger.steps)
            assertEquals(LocalState.PENDING, rec.state)
            assertEquals(deviceId, rec.deviceId)
            assertTrue(Regex("^[0-9]{6}$").matches(rec.sas))
            assertEquals(48, rec.wrappedCt.size)

            val active = x.flow.awaitActive(intervalMs = 1, maxMs = 60_000)
            assertEquals(LocalState.ACTIVE, active.state)
            assertEquals(keyId, active.keys.single().keyId)

            val trial = x.flow.trialOpen(active.keys.single())
            assertEquals(TrialResult(hasPh = true, hasKh = false), trial)
            assertEquals(FingerStep.TRIAL, x.finger.steps.last())
            assertTrue(x.flow.keysValid())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun annulerenBijVingerLaatNietsAchter() = runTest {
        for (step in listOf(FingerStep.WRAP, FingerStep.SIGN)) {
            val x = setup(FakeFinger(cancelAt = step))
            try {
                x.flow.claim(qr(), info)
                fail("geen fout bij annuleren ($step)")
            } catch (e: IllegalStateException) {
                assertNull(x.flow.current())
                assertFalse(x.keys.anyPresent())
            } finally {
                x.dir.deleteRecursively()
            }
        }
    }

    @Test fun andereSasVanServerBreektAf() = runTest {
        val x = setup { it.tamperSas = true }
        try {
            x.flow.claim(qr(), info)
            fail()
        } catch (e: PairingError) {
            assertEquals(PairingError.SasMismatch, e)
            assertNull(x.flow.current())
            assertFalse(x.keys.anyPresent())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun verkeerdQrGeheimGeeftMacFout() = runTest {
        val x = setup()
        try {
            val wrong = PairingQr.parse("hs1p:$pairingId." + B64u.encode(ByteArray(16) { 9 }))!!
            x.flow.claim(wrong, info)
            fail()
        } catch (e: PairingError.Api) {
            assertEquals("pairing_mac_invalid", e.code)
            assertNull(x.flow.current())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun ingetrokkenWistLokaal() = runTest {
        val x = setup()
        try {
            x.flow.claim(qr(), info)
            x.server.revoke = true
            try {
                x.flow.awaitActive(intervalMs = 1)
                fail()
            } catch (e: PairingError) {
                assertEquals(PairingError.Revoked, e)
            }
            assertNull(x.flow.current())
            assertFalse(x.keys.anyPresent())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun ongeldigeSleutelsWissenAlles() = runTest {
        val x = setup()
        try {
            x.flow.claim(qr(), info)
            x.flow.awaitActive(intervalMs = 1)
            x.keys.invalid = true
            assertFalse(x.flow.keysValid())
            assertNull(x.flow.current())
            assertFalse(x.keys.anyPresent())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun ongeldigBijProefGeeftOpnieuwKoppelen() = runTest {
        val x = setup()
        try {
            x.flow.claim(qr(), info)
            val rec = x.flow.awaitActive(intervalMs = 1)
            x.keys.invalid = true
            try {
                x.flow.trialOpen(rec.keys.single())
                fail()
            } catch (e: PairingError) {
                assertEquals(PairingError.KeysInvalidated, e)
            }
            assertNull(x.flow.current())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun toestelLabelOpgeschoond() {
        assertEquals("Galaxy Fold", DeviceInfo.clean("  Galaxy\u0000\n  Fold\t", 64, "x"))
        assertEquals("x", DeviceInfo.clean("\u0001\u0002", 64, "x"))
        assertEquals("x", DeviceInfo.clean(null, 64, "x"))
        assertEquals(64, DeviceInfo.clean("a".repeat(100), 64, "x").length)
        val emoji = "😀".repeat(70)
        assertEquals(64, DeviceInfo.clean(emoji, 64, "x").codePointCount(0, 128))
    }

    // ───────────── 401/404 zijn tijdelijk: niets wissen (§13.3 stap 5) ─────────────

    @Test fun status401Of404WistNiets() = runTest {
        for (code in listOf(401, 404)) {
            val x = setup()
            try {
                x.flow.claim(qr(), info)
                val active = x.flow.awaitActive(intervalMs = 1)
                x.server.statusError = code
                try {
                    x.flow.refresh(transientOk = true)
                    fail("geen fout bij $code")
                } catch (e: PairingError) {
                    assertEquals(PairingError.DeviceUnknown(code, null), e)
                }
                val still = x.flow.current()
                assertNotNull("koppelbestand blijft bij $code", still)
                assertEquals(active.deviceId, still!!.deviceId)
                assertEquals(LocalState.ACTIVE, still.state)
                assertTrue("sleutels blijven bij $code", x.keys.present(still.slot))
                assertEquals(0, x.keys.deleted)
                // weer bereikbaar → gewoon verder
                x.server.statusError = null
                assertEquals(LocalState.ACTIVE, x.flow.refresh()!!.state)
            } finally {
                x.dir.deleteRecursively()
            }
        }
    }

    @Test fun wachtenOpLaptop404WistNiets() = runTest {
        val x = setup { it.activeAfter = 99 }
        try {
            val rec = x.flow.claim(qr(), info)
            x.server.statusError = 404
            try {
                x.flow.awaitActive(intervalMs = 1)
                fail()
            } catch (e: PairingError) {
                assertEquals(PairingError.DeviceUnknown(404, null), e)
            }
            assertEquals(rec.deviceId, x.flow.current()!!.deviceId)
            assertEquals(LocalState.PENDING, x.flow.current()!!.state)
            assertTrue(x.keys.anyPresent())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun netwerkfoutWistNiets() = runTest {
        var down = false
        val x = setup(transport = { srv ->
            nl.icthorse.horsesafe.net.HttpTransport { req -> if (down) throw java.io.IOException("weg") else srv.execute(req) }
        })
        try {
            x.flow.claim(qr(), info)
            x.flow.awaitActive(intervalMs = 1)
            down = true
            assertNull(x.flow.refresh(transientOk = true))
            try {
                x.flow.refresh()
                fail()
            } catch (e: PairingError.Api) {
                assertEquals(0, e.status)
            }
            assertNotNull(x.flow.current())
            assertTrue(x.keys.anyPresent())
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun klokwaarschuwingBij401() = runTest {
        val now = 1_800_000_000_000L
        val x = setup(clock = { now })
        try {
            x.flow.claim(qr(), info)
            x.server.statusError = 401
            // Server 2 min achter de telefoon → telefoon loopt 120 s voor
            x.server.dateMillis = now - 120_000
            assertEquals(PairingError.DeviceUnknown(401, 120), runCatching { x.flow.refresh() }.exceptionOrNull())
            // Telefoon loopt 90 s achter
            x.server.dateMillis = now + 90_000
            assertEquals(PairingError.DeviceUnknown(401, -90), runCatching { x.flow.refresh() }.exceptionOrNull())
            // Binnen 60 s: geen klokwaarschuwing
            x.server.dateMillis = now - 59_000
            assertEquals(PairingError.DeviceUnknown(401, null), runCatching { x.flow.refresh() }.exceptionOrNull())
            // Geen Date-header, of 404: geen klokwaarschuwing
            x.server.dateMillis = null
            assertEquals(PairingError.DeviceUnknown(401, null), runCatching { x.flow.refresh() }.exceptionOrNull())
            x.server.statusError = 404
            x.server.dateMillis = now - 120_000
            assertEquals(PairingError.DeviceUnknown(404, null), runCatching { x.flow.refresh() }.exceptionOrNull())
            assertNotNull(x.flow.current())
            val txt = nl.icthorse.horsesafe.ui.PairingViewModel.errorText(PairingError.DeviceUnknown(401, 120))
            assertTrue(txt, txt.contains("klok") && txt.contains("2 min voor") && txt.contains("niets gewist"))
        } finally {
            x.dir.deleteRecursively()
        }
    }

    // ───────────── opnieuw koppelen: oude koppeling blijft tot de nieuwe claim slaagt ─────────────

    @Test fun mislukteNieuweClaimLaatOudeKoppelingStaan() = runTest {
        val x = setup()
        try {
            x.flow.claim(qr(), info)
            val old = x.flow.awaitActive(intervalMs = 1)
            assertEquals(KeySlot.A, old.slot)
            val oldDev = x.keys.devPub(KeySlot.A)!!

            // a. claim geweigerd door de server
            x.server.claimError = 409
            try {
                x.flow.claim(qr(), info)
                fail()
            } catch (e: PairingError.Api) {
                assertEquals(409, e.status)
            }
            // b. geannuleerd bij de vinger
            val y = PairingFlow(x.keys, FakeFinger(cancelAt = FingerStep.SIGN), DeviceApi(x.server), DeviceStore(x.dir))
            x.server.claimError = null
            try {
                y.claim(qr(), info)
                fail()
            } catch (e: IllegalStateException) {
                // verwacht
            }
            // c. andere SAS van de server
            x.server.tamperSas = true
            try {
                x.flow.claim(qr(), info)
                fail()
            } catch (e: PairingError) {
                assertEquals(PairingError.SasMismatch, e)
            }
            x.server.tamperSas = false

            assertEquals(listOf(KeySlot.A, KeySlot.B, KeySlot.B, KeySlot.B), x.keys.created)
            val still = x.flow.current()!!
            assertEquals(LocalState.ACTIVE, still.state)
            assertEquals(KeySlot.A, still.slot)
            assertArrayEquals("oude K_dev onaangetast", oldDev, x.keys.devPub(KeySlot.A))
            assertFalse("tijdelijke set gewist", x.keys.present(KeySlot.B))
            assertEquals(0, x.keys.deleted)
            assertTrue(x.flow.keysValid())

            // d. geslaagde nieuwe claim: omwisselen naar B, oude set weg
            val next = x.flow.claim(qr(), info)
            assertEquals(KeySlot.B, next.slot)
            assertEquals(LocalState.PENDING, x.flow.current()!!.state)
            assertEquals(KeySlot.B, x.flow.current()!!.slot)
            assertFalse(x.keys.present(KeySlot.A))
            assertTrue(x.keys.present(KeySlot.B))
            assertEquals(LocalState.ACTIVE, x.flow.awaitActive(intervalMs = 1).state)
            assertEquals(TrialResult(hasPh = true, hasKh = false), x.flow.trialOpen(x.flow.current()!!.keys.single()))
        } finally {
            x.dir.deleteRecursively()
        }
    }

    @Test fun toestelLabelZonderOpmaaktekens() {
        assertEquals("GalaxyFold", DeviceInfo.clean("Galaxy\u202eFold", 64, "x"))
        assertEquals("Fold", DeviceInfo.clean("Fo\u200bld\u2066", 64, "x"))
        assertEquals("a b", DeviceInfo.clean("a\u2028 b\u2029", 64, "x"))
        assertEquals("Fold", DeviceInfo.clean("Fold\ud800", 64, "x"))
        assertEquals("Fold", DeviceInfo.clean("\udc00Fold\ufeff", 64, "x"))
        assertEquals("x", DeviceInfo.clean("\u202e\u200b", 64, "x"))
        assertEquals("Téléphone 📱", DeviceInfo.clean("Téléphone 📱", 64, "x"))
        listOf(0x202E, 0x200B, 0x2028, 0x2029, 0xD800, 0xFEFF, 0x00).forEach { assertFalse(Integer.toHexString(it), DeviceInfo.allowed(it)) }
        listOf('a'.code, 0xE9, 0x1F4F1, ' '.code).forEach { assertTrue(Integer.toHexString(it), DeviceInfo.allowed(it)) }
    }
}
