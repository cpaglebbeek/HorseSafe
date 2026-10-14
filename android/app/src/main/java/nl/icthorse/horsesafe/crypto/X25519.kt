package nl.icthorse.horsesafe.crypto

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * X25519 (RFC 7748) via de platform-provider ("XDH": Conscrypt op Android, SunEC op de JVM). Geen Tink:
 * de vectortest (`SealV2VectorTest`) slaagt met de platform-XDH (HARDWARE_KEYS §7.2).
 *
 * Sleutels gaan als ruwe 32 bytes in en uit. Import via vaste DER-omhulsels (PKCS#8 / X.509 met OID
 * 1.3.101.110); de provider past de clamping uit RFC 7748 zelf toe, zodat een ruwe scalar (`seed`) gelijk
 * werkt als in WebCrypto en Python `cryptography`.
 */
object X25519 {
    const val KEY_LEN = 32

    private val PKCS8_PREFIX = hex("302e020100300506032b656e04220420")
    private val X509_PREFIX = hex("302a300506032b656e032100")

    /** u = 9: het basispunt; X25519(sk, 9) = publieke sleutel. */
    private val BASE_POINT = ByteArray(KEY_LEN).also { it[0] = 9 }

    /** 32 willekeurige bytes (sk_c, §2: "32 willekeurige bytes"). */
    fun newPrivate(random: SecureRandom = SecureRandom()): ByteArray = ByteArray(KEY_LEN).also { random.nextBytes(it) }

    /** Ruwe publieke sleutel bij een ruwe privésleutel. */
    fun publicKey(sk: ByteArray): ByteArray = agree(sk, BASE_POINT)

    /**
     * Gedeeld geheim; weigert het nul-resultaat (lage-orde-punt), zoals §12.5 eist.
     * @throws IllegalArgumentException bij een ongeldige sleutel of nul-resultaat.
     */
    fun sharedSecret(sk: ByteArray, peerPublic: ByteArray): ByteArray {
        val ss = try {
            agree(sk, peerPublic)
        } catch (e: IllegalArgumentException) {
            throw e
        } catch (e: Exception) {
            // Sommige providers weigeren een lage-orde-punt zelf al (met een eigen uitzondering).
            throw IllegalArgumentException("X25519 mislukt")
        }
        if (ss.all { it == 0.toByte() }) throw IllegalArgumentException("X25519: gedeeld geheim is nul")
        return ss
    }

    private fun agree(sk: ByteArray, pub: ByteArray): ByteArray {
        require(sk.size == KEY_LEN && pub.size == KEY_LEN) { "X25519-sleutel moet 32 bytes zijn" }
        val kf = KeyFactory.getInstance("XDH")
        val pkcs8 = PKCS8_PREFIX + sk
        val priv: PrivateKey
        try {
            priv = kf.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
        } finally {
            pkcs8.fill(0)
        }
        val peer: PublicKey = kf.generatePublic(X509EncodedKeySpec(X509_PREFIX + pub))
        val ka = KeyAgreement.getInstance("XDH")
        ka.init(priv)
        ka.doPhase(peer, true)
        val out = ka.generateSecret()
        require(out.size == KEY_LEN) { "X25519: onverwachte lengte" }
        return out
    }

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
