package nl.icthorse.horsesafe.crypto

import java.util.Base64

/**
 * base64url zonder '=' (RFC 4648 §5), zoals overal in HARDWARE_KEYS §12-§13.
 *
 * Decoderen is strikt: alleen `A-Z a-z 0-9 - _`, geen opvulling, geen witruimte, en de code moet
 * canoniek zijn (opnieuw coderen geeft exact dezelfde tekst; ongebruikte bits = 0). Zo heeft elke
 * byte-reeks precies één tekstvorm, net als bij de server-validatie.
 */
object B64u {
    private val ALPHABET = Regex("^[A-Za-z0-9_-]*$")

    fun encode(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)

    /** @throws IllegalArgumentException bij een ongeldige of niet-canonieke code. */
    fun decode(s: String): ByteArray {
        require(ALPHABET.matches(s)) { "geen base64url" }
        require(s.length % 4 != 1) { "ongeldige base64url-lengte" }
        val out = Base64.getUrlDecoder().decode(s)
        require(encode(out) == s) { "niet-canonieke base64url" }
        return out
    }

    /** Decodeert en eist precies [len] bytes. */
    fun decode(s: String, len: Int): ByteArray {
        val out = decode(s)
        if (out.size != len) {
            out.fill(0)
            throw IllegalArgumentException("verwacht $len bytes")
        }
        return out
    }
}
