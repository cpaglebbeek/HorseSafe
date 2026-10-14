package nl.icthorse.horsesafe.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** HKDF-SHA256 (RFC 5869) en HMAC-SHA256; alleen JCA, geen Android-afhankelijkheid (JVM-testbaar). */
object Hkdf {
    private const val HASH_LEN = 32

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /**
     * @param salt null of leeg = 32 nulbytes (RFC 5869 §2.2); in HorseSafe altijd expliciet meegegeven.
     */
    fun sha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * HASH_LEN) { "ongeldige HKDF-lengte" }
        val s = if (salt == null || salt.isEmpty()) ByteArray(HASH_LEN) else salt
        val prk = hmacSha256(s, ikm)
        try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            val out = ByteArray(length)
            var t = ByteArray(0)
            var pos = 0
            var counter = 1
            while (pos < length) {
                mac.update(t)
                mac.update(info)
                mac.update(counter.toByte())
                val next = mac.doFinal()
                t.fill(0)
                t = next
                val n = minOf(t.size, length - pos)
                System.arraycopy(t, 0, out, pos, n)
                pos += n
                counter++
            }
            t.fill(0)
            return out
        } finally {
            prk.fill(0)
        }
    }

    fun sha256(ikm: ByteArray, salt: ByteArray?, info: String, length: Int = HASH_LEN): ByteArray =
        sha256(ikm, salt, info.toByteArray(Charsets.UTF_8), length)
}
