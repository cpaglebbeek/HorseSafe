package nl.icthorse.horsesafe.pairing

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.crypto.PairV1
import nl.icthorse.horsesafe.crypto.SealV2
import nl.icthorse.horsesafe.keystore.KeyLevel
import nl.icthorse.horsesafe.keystore.KeySlot
import nl.icthorse.horsesafe.keystore.KeysInvalidatedException
import nl.icthorse.horsesafe.keystore.PhoneKeyMaterial
import nl.icthorse.horsesafe.keystore.PhoneKeys
import nl.icthorse.horsesafe.net.DeviceAuth
import nl.icthorse.horsesafe.net.HttpRequest
import nl.icthorse.horsesafe.net.HttpResponse
import nl.icthorse.horsesafe.net.HttpTransport
import nl.icthorse.horsesafe.report.StrictJson
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/** Gedeelde nep-onderdelen voor de koppeltests (geen Keystore, geen vinger, geen netwerk). */
internal object PairFixture {
    const val PAIRING_ID = "5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d"
    const val DEVICE_ID = "c0ffee00-1234-4abc-9def-0123456789ab"
    const val KEY_ID = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a"
    const val VAULT_ID = "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"
    val S = ByteArray(16) { (it + 1).toByte() }
    val PH = ByteArray(32) { 3 }

    fun qrText(secret: ByteArray = S) = "hs1p:$PAIRING_ID." + B64u.encode(secret)
}

/** Nep-Keystore: zelfde interface, software-sleutels per [KeySlot]; telt aanroepen en kan "ongeldig" worden. */
internal class FakeKeys : PhoneKeys {
    class Set(val dev: KeyPair, val bio: KeyPair, val wrap: SecretKey)

    val sets = mutableMapOf<KeySlot, Set>()
    var challenge: ByteArray? = null
    var invalid = false
    var deleted = 0
    val created = mutableListOf<KeySlot>()

    /** Publieke K_dev van een set (om te zien welke sleutels er staan). */
    fun devPub(slot: KeySlot): ByteArray? = sets[slot]?.dev?.public?.encoded

    private fun ec() = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    override fun create(attChallenge: ByteArray, slot: KeySlot): PhoneKeyMaterial {
        challenge = attChallenge
        created += slot
        val set = Set(ec(), ec(), KeyGenerator.getInstance("AES").apply { init(256) }.generateKey())
        sets[slot] = set
        val chain = listOf(ByteArray(300) { 1 }, ByteArray(300) { 2 })
        return PhoneKeyMaterial(set.dev.public.encoded, set.bio.public.encoded, chain, chain, KeyLevel.STRONGBOX, KeyLevel.TEE, KeyLevel.TEE)
    }

    private fun set(slot: KeySlot): Set {
        if (invalid) throw KeysInvalidatedException()
        return sets[slot] ?: throw KeysInvalidatedException()
    }

    override fun wrapCipher(slot: KeySlot): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, set(slot).wrap) }

    override fun unwrapCipher(slot: KeySlot, iv: ByteArray): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, set(slot).wrap, GCMParameterSpec(128, iv)) }

    override fun biosigSignature(slot: KeySlot): Signature =
        Signature.getInstance("SHA256withECDSA").apply { initSign(set(slot).bio.private) }

    override fun signDev(slot: KeySlot, message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run { initSign(sets.getValue(slot).dev.private); update(message); sign() }

    override fun present(slot: KeySlot): Boolean = slot in sets

    /** Staat er nog een sleutelset? */
    fun anyPresent(): Boolean = sets.isNotEmpty()

    override fun delete(slot: KeySlot) {
        sets.remove(slot)
    }

    override fun deleteAll() {
        deleted++
        sets.clear()
    }
}

internal class FakeFinger(var cancelAt: FingerStep? = null) : Finger {
    val steps = mutableListOf<FingerStep>()
    override suspend fun cipher(cipher: Cipher, step: FingerStep): Cipher {
        steps += step
        if (step == cancelAt) throw IllegalStateException("geannuleerd")
        return cipher
    }

    override suspend fun signature(signature: Signature, step: FingerStep): Signature {
        steps += step
        if (step == cancelAt) throw IllegalStateException("geannuleerd")
        return signature
    }
}

/** Nep-server: controleert mac_srv, sig_biosig en de device-handtekening; levert status en kopie. */
internal class FakeServer(val keys: FakeKeys) : HttpTransport {
    var claimBody: Map<*, *>? = null
    var statusCalls = 0
    var activeAfter = 2
    var revoke = false
    var tamperSas = false

    /** Status-endpoint antwoordt met deze HTTP-fout (401/404/503) in plaats van een status. */
    var statusError: Int? = null

    /** `Date`-header (ms) bij een foutantwoord; null = geen header. */
    var dateMillis: Long? = null

    /** Claim mislukt met deze HTTP-status (bv. 409 too_many_devices). */
    var claimError: Int? = null

    override fun execute(req: HttpRequest): HttpResponse = when {
        req.path == "/devices/pairings/${PairFixture.PAIRING_ID}/claim" -> claim(req)
        req.path == "/device/v1/status" && statusError != null -> {
            statusCalls++
            HttpResponse(statusError!!, "{\"detail\":{\"error\":\"device_auth_failed\"}}", dateMillis)
        }
        req.path == "/device/v1/status" -> {
            verifyDev(req)
            statusCalls++
            when {
                revoke -> HttpResponse(200, "{\"device_id\":\"${PairFixture.DEVICE_ID}\",\"state\":\"revoked\",\"keys\":[]}")
                statusCalls < activeAfter -> HttpResponse(200, "{\"device_id\":\"${PairFixture.DEVICE_ID}\",\"state\":\"pending\",\"keys\":[]}")
                else -> HttpResponse(
                    200,
                    "{\"device_id\":\"${PairFixture.DEVICE_ID}\",\"state\":\"active\",\"keys\":[{\"key_id\":\"${PairFixture.KEY_ID}\",\"vault_id\":\"${PairFixture.VAULT_ID}\",\"label\":\"Galaxy\"}]}",
                )
            }
        }
        req.path == "/device/v1/keys/${PairFixture.KEY_ID}/sealed" -> {
            verifyDev(req)
            val pk = B64u.decode(claimBody!!["pk_c"] as String, 32)
            val sealed = SealV2.seal(pk, PairFixture.PH, null, "store", PairFixture.VAULT_ID, PairFixture.KEY_ID, PairFixture.KEY_ID)
            HttpResponse(200, StrictJson.write(linkedMapOf("key_id" to PairFixture.KEY_ID, "vault_id" to PairFixture.VAULT_ID, "sealed" to sealed)))
        }
        else -> HttpResponse(404, "{\"detail\":{\"error\":\"not_found\"}}")
    }

    private fun claim(req: HttpRequest): HttpResponse {
        val b = StrictJson.parse(String(req.body!!, Charsets.UTF_8)) as Map<*, *>
        claimError?.let { return HttpResponse(it, "{\"detail\":{\"error\":\"too_many_devices\"}}") }
        claimBody = b
        val f = PairV1.Fields(PairFixture.PAIRING_ID, b["pk_c"] as String, b["k_dev_pub"] as String, b["k_biosig_pub"] as String,
            b["label"] as String, b["model"] as String, b["app_version"] as String)
        val t = PairV1.transcript(f)
        val kSrv = PairV1.kSrv(PairFixture.S)
        if (b["mac_srv"] != B64u.encode(PairV1.mac(kSrv, t))) return HttpResponse(400, "{\"detail\":{\"error\":\"pairing_mac_invalid\"}}")
        assertEquals("mac_web", B64u.encode(PairV1.mac(PairV1.kWeb(PairFixture.S), t)), b["mac_web"])
        assertArrayEquals("att_challenge", PairV1.attChallenge(PairFixture.PAIRING_ID, kSrv), keys.challenge)
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(B64u.decode(b["k_biosig_pub"] as String)))
        val okSig = Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(t); verify(B64u.decode(b["sig_biosig"] as String)) }
        if (!okSig) return HttpResponse(400, "{\"detail\":{\"error\":\"signature_invalid\"}}")
        val sas = if (tamperSas) "000000" else PairV1.sas(t)
        return HttpResponse(201, "{\"device_id\":\"${PairFixture.DEVICE_ID}\",\"sas\":\"$sas\"}")
    }

    private fun verifyDev(req: HttpRequest) {
        val h = req.headers
        assertEquals(PairFixture.DEVICE_ID, h["X-HS-Device"])
        val msg = DeviceAuth.message(req.method, "/api" + req.path, h["X-HS-Ts"]!!.toLong(), h["X-HS-Nonce"]!!, ByteArray(0))
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(B64u.decode(claimBody!!["k_dev_pub"] as String)))
        val ok = Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(msg); verify(B64u.decode(h["X-HS-Sig"]!!)) }
        assertTrue("device-handtekening", ok)
    }
}

