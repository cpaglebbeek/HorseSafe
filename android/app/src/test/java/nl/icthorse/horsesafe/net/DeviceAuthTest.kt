package nl.icthorse.horsesafe.net

import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import nl.icthorse.horsesafe.crypto.B64u
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Device-handtekening D (HARDWARE_KEYS §13.6): exacte getekende tekst en headers. */
class DeviceAuthTest {
    private val emptyHash = B64u.encode(MessageDigest.getInstance("SHA-256").digest(ByteArray(0)))

    @Test fun getekendeTekstExact() {
        val m = DeviceAuth.message("GET", "/api/device/v1/status", 1_760_000_000L, "AAAAAAAAAAAAAAAAAAAAAA", ByteArray(0))
        val expected = "HSv2 dev\u0000GET\u0000/api/device/v1/status\u00001760000000\u0000AAAAAAAAAAAAAAAAAAAAAA\u0000$emptyHash"
        assertArrayEquals(expected.toByteArray(Charsets.UTF_8), m)
        // SHA-256 van een lege body = 47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU
        assertEquals("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", emptyHash)
    }

    @Test fun bodyEnQueryTellenMee() {
        val body = "{\"a\":1}".toByteArray()
        val m = String(DeviceAuth.message("POST", "/api/device/v1/x?y=1", 5, "n", body), Charsets.UTF_8)
        assertTrue(m.contains("\u0000/api/device/v1/x?y=1\u0000"))
        assertTrue(m.endsWith("\u0000" + B64u.encode(MessageDigest.getInstance("SHA-256").digest(body))))
    }

    @Test fun ongeldigeInvoerGeweigerd() {
        listOf<() -> Unit>(
            { DeviceAuth.message("get", "/api/x", 1, "n", ByteArray(0)) },
            { DeviceAuth.message("GET", "/device/v1/status", 1, "n", ByteArray(0)) },
            { DeviceAuth.message("GET", "/api/x\u0000", 1, "n", ByteArray(0)) },
        ).forEach {
            try {
                it()
                fail("geaccepteerd")
            } catch (e: IllegalArgumentException) {
                // goed
            }
        }
    }

    @Test fun headersEnEchteHandtekening() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val signer = DevKeySigner { msg -> Signature.getInstance("SHA256withECDSA").run { initSign(kp.private); update(msg); sign() } }
        val nonce = DeviceAuth.newNonce()
        assertEquals(16, B64u.decode(nonce).size)
        val h = DeviceAuth.headers("5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d", "GET", "/api/device/v1/status", ByteArray(0), signer, 42L, nonce)
        assertEquals(listOf("X-HS-Device", "X-HS-Ts", "X-HS-Nonce", "X-HS-Sig"), h.keys.toList())
        assertEquals("42", h["X-HS-Ts"])
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(kp.public)
            update(DeviceAuth.message("GET", "/api/device/v1/status", 42L, nonce, ByteArray(0)))
            verify(B64u.decode(h["X-HS-Sig"]!!))
        }
        assertTrue("handtekening (DER) klopt", ok)
    }
}
