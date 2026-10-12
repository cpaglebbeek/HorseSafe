package nl.icthorse.horsesafe.pin

/**
 * Implementatie van [SecretBuffer] op één CharArray met vaste capaciteit.
 *
 * - Geen String, geen kopie die blijft bestaan: [useChars] leent de array zelf als hij vol is, en
 *   anders een tijdelijke kopie van precies [length] tekens die na het blok direct wordt gewist.
 * - [toString] geeft altijd [SecretBuffer.HIDDEN]; `equals`/`hashCode` zijn identiteit (van [Any]).
 * - Na [wipe] gooit elke lees- of schrijfactie [IllegalStateException].
 */
class CharSecretBuffer(override val capacity: Int = SecretBuffer.PIN_LENGTH) : SecretBuffer {
    init {
        require(capacity > 0) { "capaciteit moet positief zijn" }
    }

    private val chars = CharArray(capacity)
    private var len = 0
    private var wiped = false

    override val length: Int
        @Synchronized get() = len

    override val isWiped: Boolean
        @Synchronized get() = wiped

    @Synchronized
    override fun append(c: Char) {
        ensureLive()
        check(len < capacity) { "buffer is vol" }
        chars[len++] = c
    }

    @Synchronized
    override fun removeLast() {
        ensureLive()
        check(len > 0) { "buffer is leeg" }
        len--
        chars[len] = '\u0000'
    }

    @Synchronized
    override fun get(index: Int): Char {
        ensureLive()
        if (index < 0 || index >= len) throw IndexOutOfBoundsException("positie buiten de buffer")
        return chars[index]
    }

    @Synchronized
    override fun <T> useChars(block: (CharArray) -> T): T {
        ensureLive()
        if (len == capacity) return block(chars)
        val tmp = chars.copyOf(len)
        try {
            return block(tmp)
        } finally {
            tmp.fill('\u0000')
        }
    }

    @Synchronized
    override fun wipe() {
        chars.fill('\u0000')
        len = 0
        wiped = true
    }

    override fun toString(): String = SecretBuffer.HIDDEN

    private fun ensureLive() {
        check(!wiped) { "buffer is gewist" }
    }
}
