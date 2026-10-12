package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.fido.ctap.Ctap2Session
import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.yubikey.api.AlwaysUvOutcome
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.ConfigOps
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.Transport
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * De adapters met de echte yubikit 3.0.1-code (Ctap2Session, ClientPin + PinUvAuthProtocolV2,
 * Config, CredentialManagement) tegen een nep-authenticator achter CTAPHID-framing.
 */
class CtapPhaseTest {

    private val pin = "abcdefghjkmnpqrstuvwx23456789abcdefghjkmnpqrstuvwx23456789abcde" // 63, testwaarde

    private fun phase(fake: FakeAuthenticator): YubikitCtapPhase =
        YubikitCtapPhase(Transport.USB, Ctap2Session(FakeHidConnection(fake::handle)))

    private fun withPin(fake: FakeAuthenticator) = fake.apply { options["clientPin"] = true }

    @Test
    fun pinTokenGaatAltijdMetPermissieNaarSubcommand09() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val p = phase(fake)
        val secret = TestSecret(pin)
        val token = p.pin.pinToken(secret, Permission.CM)
        val req = fake.clientPinRequests().last()
        assertEquals(0x09, req[2])
        assertEquals(0x04, req[9]) // CM, nooit null (kritiek 1)
        assertNull(req[10]) //        geen rpId bij CM
        assertEquals(2, req[1]) //    PinUvAuthProtocol V2
        assertFalse(0x05 in fake.subcommands())
        assertArrayEquals(FakeAuthenticator.pinHashOf(pin.toCharArray()), fake.lastPinHash())
        assertEquals(Permission.CM, token.permission)
        assertFalse(token.toString().contains("40")) // geen tokenbytes in toString
        p.close()
        assertTrue(token.isWiped)
    }

    @Test
    fun f7bOefencontroleIsCmToken() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val p = phase(fake)
        p.pin.pinToken(TestSecret(pin), Permission.CM).use { }
        assertEquals(listOf(0x02, 0x09), fake.subcommands())
        assertEquals(0x04, fake.clientPinRequests().last()[9])
    }

    @Test
    fun mcTokenAlleenMetKeuringsRpId() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val p = phase(fake)
        p.pin.pinToken(TestSecret(pin), Permission.MC, AttestOps.KEURING_RP_ID)
        val req = fake.clientPinRequests().last()
        assertEquals(0x01, req[9])
        assertEquals(AttestOps.KEURING_RP_ID, req[10])
        val before = fake.requests.size
        for ((perm, rp) in listOf(Permission.MC to null, Permission.MC to "x.invalid", Permission.ACFG to AttestOps.KEURING_RP_ID)) {
            try {
                p.pin.pinToken(TestSecret(pin), perm, rp)
                fail("$perm/$rp")
            } catch (e: IllegalArgumentException) {
            }
        }
        assertEquals(before, fake.requests.size) // niets naar de sleutel
    }

    @Test
    fun zonderPinUvAuthTokenNooitTerugvalOp05() = runBlocking {
        val fake = withPin(FakeAuthenticator()).apply { options.remove("pinUvAuthToken") }
        val p = phase(fake)
        try {
            p.pin.pinToken(TestSecret(pin), Permission.ACFG)
            fail()
        } catch (e: KeyError.NotSupported) {
        }
        assertTrue(fake.clientPinRequests().isEmpty())
    }

    @Test
    fun foutePinGeeftPinInvalidMetVersePogingen() = runBlocking {
        val fake = withPin(FakeAuthenticator()).apply { pinTokenError = 0x31; pinRetries = 7 }
        val p = phase(fake)
        try {
            p.pin.pinToken(TestSecret(pin), Permission.CM)
            fail()
        } catch (e: KeyError.PinInvalid) {
            assertEquals(7, e.retriesLeft)
            assertNull(e.cause)
        }
    }

    @Test
    fun pinAuthBlockedEnPolicy() = runBlocking {
        for ((code, type) in listOf(0x34 to KeyError.PinAuthBlocked::class, 0x32 to KeyError.PinBlocked::class)) {
            val fake = withPin(FakeAuthenticator()).apply { pinTokenError = code }
            try {
                phase(fake).pin.pinToken(TestSecret(pin), Permission.BE)
                fail()
            } catch (e: KeyError) {
                assertEquals(type, e::class)
            }
        }
    }

    @Test
    fun tokenUitAndereFaseOfMetAnderePermissieWordtGeweigerd() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val a = phase(fake)
        val b = phase(fake)
        val cm = a.pin.pinToken(TestSecret(pin), Permission.CM)
        try {
            b.credMgmt.metadata(cm); fail()
        } catch (e: KeyError.TokenInvalid) {
        }
        try {
            a.config.setMinPinLength63(cm); fail()
        } catch (e: KeyError.TokenInvalid) {
        }
        a.close()
        try {
            a.credMgmt.metadata(cm); fail()
        } catch (e: KeyError.TokenInvalid) {
        }
    }

    @Test
    fun credMgmtMetadataMetCmToken() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val p = phase(fake)
        val m = p.credMgmt.metadata(p.pin.pinToken(TestSecret(pin), Permission.CM))
        assertEquals(0, m.existingResidentCredentials)
        assertEquals(25, m.maxPossibleRemainingResidentCredentials)
        val req = fake.requests.last { it.first == 0x0A }.second
        assertEquals(0x01, req[1]) // getCredsMetadata
        assertNotNull(req[4]) //      pinUvAuthParam
    }

    @Test
    fun setMinPinLength63MetEenRpId() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val p = phase(fake)
        p.config.setMinPinLength63(p.pin.pinToken(TestSecret(pin), Permission.ACFG))
        val req = fake.requests.last { it.first == 0x0D }.second
        assertEquals(0x03, req[1])
        val params = req[2] as Map<*, *>
        assertEquals(63, params[1])
        assertEquals(listOf(ConfigOps.MIN_PIN_RP_ID), params[2])
        assertEquals(false, params[3])
        assertNotNull(req[4])
        // Na de schrijfactie vers teruggelezen, niet uit de cache.
        val cfgIndex = fake.requests.indexOfLast { it.first == 0x0D }
        assertEquals(0x04, fake.requests[cfgIndex + 1].first) // direct na config: verse getInfo
        assertEquals(63, p.freshInfo().minPinLength)
    }

    @Test
    fun alwaysUvAlleenToggelenBijFalse() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val p = phase(fake)
        val t = p.pin.pinToken(TestSecret(pin), Permission.ACFG)
        assertEquals(AlwaysUvOutcome.TURNED_ON, p.config.toggleAlwaysUvIfFalse(t))
        assertEquals(1, fake.requests.count { it.first == 0x0D && it.second[1] == 0x02 })
        assertEquals(AlwaysUvOutcome.ALREADY_ON, p.config.toggleAlwaysUvIfFalse(t))
        assertEquals(1, fake.requests.count { it.first == 0x0D }) // tweede keer niets geschreven
        assertEquals(true, p.freshInfo().options["alwaysUv"])
    }

    @Test
    fun alwaysUvAfwezigIsNotSupported() = runBlocking {
        val fake = withPin(FakeAuthenticator()).apply { options.remove("alwaysUv") }
        val p = phase(fake)
        try {
            p.config.toggleAlwaysUvIfFalse(p.pin.pinToken(TestSecret(pin), Permission.ACFG)); fail()
        } catch (e: KeyError.NotSupported) {
        }
        assertEquals(0, fake.requests.count { it.first == 0x0D })
    }

    @Test
    fun keuringZonderTokenAlleenAanraking() = runBlocking {
        val fake = FakeAuthenticator() // geen PIN, alwaysUv false (YK5 vóór setPin)
        val p = phase(fake)
        val ev = p.attest.keuringCredential(null)
        val req = fake.requests.last { it.first == 0x01 }.second
        assertEquals(32, (req[1] as ByteArray).size)
        assertEquals(AttestOps.KEURING_RP_ID, (req[2] as Map<*, *>)["id"])
        assertEquals(listOf(mapOf("type" to "public-key", "alg" to -7)), req[4])
        assertEquals(mapOf("rk" to false), req[7])
        assertNull(req[8]) //  pinUvAuthParam
        assertNull(req[9]) //  pinUvAuthProtocol
        assertNull(req[10]) // enterpriseAttestation
        assertNull(req[5]) //  excludeList
        assertNull(req[6]) //  extensies
        assertEquals("packed", ev.fmt)
        assertEquals(-7, ev.alg)
        assertEquals(1, ev.x5c.size)
        assertFalse(ev.withToken)
        assertArrayEquals(req[1] as ByteArray, ev.clientDataHash)
    }

    @Test
    fun keuringZonderTokenGeweigerdAlsPinOfAlwaysUv() = runBlocking {
        for (f in listOf(withPin(FakeAuthenticator()), FakeAuthenticator().apply { options["alwaysUv"] = true })) {
            try {
                phase(f).attest.keuringCredential(null); fail()
            } catch (e: KeyError.PinUvAuthTokenRequired) {
            }
            assertEquals(0, f.requests.count { it.first == 0x01 })
        }
    }

    @Test
    fun keuringMetMcToken() = runBlocking {
        val fake = withPin(FakeAuthenticator())
        val p = phase(fake)
        val t = p.pin.pinToken(TestSecret(pin), Permission.MC, AttestOps.KEURING_RP_ID)
        val ev = p.attest.keuringCredential(t)
        val req = fake.requests.last { it.first == 0x01 }.second
        assertArrayEquals(fake.v2.authenticate(fake.pinToken, req[1] as ByteArray), req[8] as ByteArray)
        assertEquals(2, req[9])
        assertTrue(ev.withToken)
        // Een CM-token mag hier niet.
        try {
            p.attest.keuringCredential(p.pin.pinToken(TestSecret(pin), Permission.CM)); fail()
        } catch (e: KeyError.TokenInvalid) {
        }
    }

    @Test
    fun setPinLeestDaarnaVers() = runBlocking {
        val fake = FakeAuthenticator()
        val p = phase(fake)
        p.pin.setPin(TestSecret(pin))
        assertEquals(0x03, fake.subcommands().last())
        assertEquals(0x04, fake.requests.last().first)
        assertEquals(true, p.option("clientPin"))
        // Tweede keer: PIN staat er al → geweigerd zonder verzoek.
        val n = fake.requests.size
        try {
            p.pin.setPin(TestSecret(pin)); fail()
        } catch (e: KeyError.OperationDenied) {
        }
        assertEquals(n, fake.requests.size)
    }

    @Test
    fun pinVormWordtVooraf_gecontroleerd() = runBlocking {
        val p = phase(FakeAuthenticator())
        for (bad in listOf("abc", "a".repeat(64), "abcdé", "abc defg")) {
            try {
                p.pin.setPin(TestSecret(bad)); fail(bad.length.toString())
            } catch (e: IllegalArgumentException) {
                assertFalse(e.message!!.contains(bad))
            }
        }
    }

    @Test
    fun freshInfoGeeftPogingenEnCanoniekeAaguid() = runBlocking {
        val fake = withPin(FakeAuthenticator()).apply { pinRetries = 6; options["uv"] = true; options["bioEnroll"] = false }
        val info = phase(fake).freshInfo()
        assertEquals("10111213-1415-1617-1819-1a1b1c1d1e1f", info.aaguid.uuid)
        assertEquals(6, info.pinRetries)
        assertEquals(3, info.uvRetries)
        assertEquals(listOf(2, 1), info.pinUvAuthProtocols)
        assertEquals(1, info.maxRpidsForSetMinPinLength)
    }

    @Test
    fun protocolV1AlsV2Ontbreekt() = runBlocking {
        val fake = withPin(FakeAuthenticator()).apply { protocols = listOf(1) }
        val p = phase(fake)
        assertEquals(1, p.protocol.version)
        val none = withPin(FakeAuthenticator()).apply { protocols = emptyList() }
        try {
            phase(none).pin.pinToken(TestSecret(pin), Permission.CM); fail()
        } catch (e: KeyError.NotSupported) {
        }
    }
}
