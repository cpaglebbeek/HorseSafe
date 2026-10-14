package nl.icthorse.horsesafe.net

import java.security.MessageDigest
import java.security.SecureRandom
import nl.icthorse.horsesafe.crypto.B64u

/** Ondertekenen met K_dev (EC P-256, geen UV): levert ECDSA-SHA256 in DER. Implementatie: `keystore/`. */
fun interface DevKeySigner {
    fun sign(message: ByteArray): ByteArray
}

/**
 * Device-handtekening D (HARDWARE_KEYS §13.6).
 *
 * Getekende tekst: UTF-8("HSv2 dev" ‖ "\0" ‖ METHOD ‖ "\0" ‖ PATH ‖ "\0" ‖ ts ‖ "\0" ‖ nonce ‖ "\0" ‖ b64u(SHA-256(body))),
 * met PATH = pad vanaf `/api` inclusief querystring (bv. `/api/device/v1/status`), ts = unix-seconden
 * (decimaal), nonce = b64u van 16 willekeurige bytes. Een lege body hasht als SHA-256 van 0 bytes.
 */
object DeviceAuth {
    const val H_DEVICE = "X-HS-Device"
    const val H_TS = "X-HS-Ts"
    const val H_NONCE = "X-HS-Nonce"
    const val H_SIG = "X-HS-Sig"
    const val NONCE_LEN = 16

    fun message(method: String, path: String, ts: Long, nonce: String, body: ByteArray): ByteArray {
        require(method.isNotEmpty() && method.all { it in 'A'..'Z' }) { "methode in hoofdletters" }
        require(path.startsWith("/api/")) { "PATH begint met /api/" }
        listOf(path, nonce).forEach { require(!it.contains('\u0000')) { "nulteken in getekend veld" } }
        val bodyHash = B64u.encode(MessageDigest.getInstance("SHA-256").digest(body))
        return listOf("HSv2 dev", method, path, ts.toString(), nonce, bodyHash).joinToString("\u0000").toByteArray(Charsets.UTF_8)
    }

    fun newNonce(random: SecureRandom = SecureRandom()): String = B64u.encode(ByteArray(NONCE_LEN).also { random.nextBytes(it) })

    /** De vier headers voor één request. */
    fun headers(
        deviceId: String,
        method: String,
        path: String,
        body: ByteArray,
        signer: DevKeySigner,
        nowSeconds: Long,
        nonce: String = newNonce(),
    ): Map<String, String> {
        val sig = signer.sign(message(method, path, nowSeconds, nonce, body))
        return linkedMapOf(H_DEVICE to deviceId, H_TS to nowSeconds.toString(), H_NONCE to nonce, H_SIG to B64u.encode(sig))
    }
}
