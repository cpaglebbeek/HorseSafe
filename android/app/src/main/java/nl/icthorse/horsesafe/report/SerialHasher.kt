package nl.icthorse.horsesafe.report

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/** HMAC-SHA256 met een app-privé sleutel. De sleutel zelf komt nooit buiten de implementatie. */
interface SerialHmacKey {
    fun hmacSha256(message: ByteArray): ByteArray
}

/**
 * Productie: niet-exporteerbare HMAC-sleutel in de Android Keystore (alias [alias]), bij eerste gebruik
 * willekeurig aangemaakt. Verdwijnt bij verwijderen van de app; er is geen back-up (A-14).
 */
class AndroidKeystoreSerialKey(private val alias: String = ALIAS) : SerialHmacKey {
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, PROVIDER)
        gen.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).build())
        return gen.generateKey()
    }

    @Synchronized
    override fun hmacSha256(message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(key()); doFinal(message) }

    companion object {
        const val PROVIDER = "AndroidKeyStore"
        const val ALIAS = "horsesafe_serial_hmac_v1"
    }
}

/** Sleutel uit bytes (tests, en JVM-fakes van andere modules). Niet voor productie. */
class RawSerialKey(key: ByteArray) : SerialHmacKey {
    private val spec = SecretKeySpec(key.copyOf(), "HmacSHA256")

    init {
        require(key.size >= 32) { "HMAC-sleutel moet minstens 32 bytes zijn" }
    }

    override fun hmacSha256(message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(spec); doFinal(message) }
}

/**
 * Serienummer → `KeyFacts.serialHmac` / `Report.serialHmac` (kritiek 8). Formaat:
 * `<keyId: 16 hex>.<HMAC-SHA256(sleutel, "horsesafe/serial/v1:" + serienummer): 64 hex>`.
 *
 * [keyId] is een afgeleide van de app-sleutel (niet van het serienummer). Daarmee ziet de vergelijking
 * dat een geïmporteerd rapport met een andere app-sleutel is gemaakt (herinstallatie, nieuwe telefoon):
 * dan is het serienummer niet vergelijkbaar (oranje), in plaats van een vals verschil (rood).
 * Het ruwe serienummer wordt nergens bewaard of gelogd.
 */
class SerialHasher(private val key: SerialHmacKey) {

    val keyId: String by lazy { hex(key.hmacSha256(KEY_ID_LABEL.toByteArray(Charsets.US_ASCII))).take(16) }

    /** null als het serienummer onbekend is (Management gaf niets): de aanroeper meldt dat expliciet. */
    fun hash(serial: Int?): String? {
        if (serial == null) return null
        val mac = key.hmacSha256("$SERIAL_LABEL$serial".toByteArray(Charsets.US_ASCII))
        return "$keyId.${hex(mac)}"
    }

    companion object {
        private const val KEY_ID_LABEL = "horsesafe/serial-key-id/v1"
        private const val SERIAL_LABEL = "horsesafe/serial/v1:"
        val FORMAT = Regex("^[0-9a-f]{16}\\.[0-9a-f]{64}$")

        fun keyIdOf(serialHmac: String): String? = if (FORMAT.matches(serialHmac)) serialHmac.substring(0, 16) else null

        internal fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }
    }
}
