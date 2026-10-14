package nl.icthorse.horsesafe.pairing

import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.crypto.PairV1

/**
 * Inhoud van de koppel-QR (HARDWARE_KEYS §13.1): `hs1p:<pairing_id>.<b64u(s)>`.
 * [secret] is het geheim `s` (16 B): na het afleiden van k_srv/k_web direct [wipe]. [toString] toont het niet.
 */
class PairingQr private constructor(val pairingId: String, val secret: ByteArray) {
    fun wipe() = secret.fill(0)

    override fun toString(): String = "PairingQr(pairingId=$pairingId, s=[verborgen])"

    companion object {
        const val PREFIX = "hs1p:"

        /** Kleine letters, 8-4-4-4-12 hex: de UUID-vorm van de server. */
        private val ID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

        /** b64u van 16 bytes = 22 tekens. */
        private const val SECRET_CHARS = 22
        private const val MAX_LEN = 80

        /**
         * Strikt: precies het voorvoegsel, één punt, een UUID in kleine letters en 22 tekens canonieke b64u.
         * Geen witruimte, geen hoofdletters in het voorvoegsel, geen extra tekst. null = geen HorseSafe-QR.
         */
        fun parse(text: String): PairingQr? {
            if (text.length > MAX_LEN || !text.startsWith(PREFIX)) return null
            val rest = text.substring(PREFIX.length)
            val dot = rest.indexOf('.')
            if (dot < 0 || rest.indexOf('.', dot + 1) >= 0) return null
            val id = rest.substring(0, dot)
            val s = rest.substring(dot + 1)
            if (!ID.matches(id) || s.length != SECRET_CHARS) return null
            val secret = try {
                B64u.decode(s, PairV1.SECRET_LEN)
            } catch (e: IllegalArgumentException) {
                return null
            }
            return PairingQr(id, secret)
        }
    }
}
