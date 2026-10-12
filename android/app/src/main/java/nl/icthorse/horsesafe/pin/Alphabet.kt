package nl.icthorse.horsesafe.pin

/**
 * PIN-alfabet van 29 tekens (open vraag 9, advies 29): kleine letters en cijfers zonder de tekens die
 * op papier of in handschrift verward worden (i, l, o, y, z, 0, 1). Alle tekens zijn ASCII, dus
 * 1 teken = 1 byte in UTF-8 (A-20).
 *
 * [valueOf] loopt altijd over het hele alfabet, zodat de rekentijd niet afhangt van welk teken het is.
 */
object Alphabet {
    const val CHARS: String = "abcdefghjkmnpqrstuvwx23456789"
    const val SIZE: Int = 29

    init {
        check(CHARS.length == SIZE)
        check(CHARS.all { it.code in 0x21..0x7e })
        check(CHARS.toSet().size == SIZE)
    }

    /** Waarde 0..28 van [c], of -1 als [c] niet in het alfabet zit. Zonder vroegtijdig stoppen. */
    fun valueOf(c: Char): Int {
        var result = -1
        val code = c.code
        for (i in 0 until SIZE) {
            // mask = -1 (alle bits) als gelijk, anders 0; zonder sprong op de geheime waarde.
            val diff = CHARS[i].code xor code
            val mask = ((diff or -diff) ushr 31) - 1
            result = (result and mask.inv()) or (i and mask)
        }
        return result
    }

    /** Teken bij waarde [v] (0..28). */
    fun charAt(v: Int): Char {
        require(v in 0 until SIZE) { "waarde buiten het alfabet" }
        return CHARS[v]
    }

    fun contains(c: Char): Boolean = valueOf(c) >= 0
}
