package nl.icthorse.horsesafe.pin

import java.security.SecureRandom

/**
 * Bron van uniforme gehele getallen in `[0, bound)`. In productie altijd [SecureRandomSource]; de
 * tests injecteren een vaste bron. (Bronbeleid A-20: in `pin/` geen niet-cryptografische RNG.)
 */
fun interface RandomSource {
    fun nextInt(bound: Int): Int
}

/** [SecureRandom.nextInt] met grens is zonder modulo-bias (afwijzingsmethode in de JDK). */
class SecureRandomSource(private val random: SecureRandom = SecureRandom()) : RandomSource {
    override fun nextInt(bound: Int): Int = random.nextInt(bound)
}

/**
 * Maakt de PIN: [SecretBuffer.PIN_LENGTH] (63) tekens, elk uniform uit [Alphabet] (29 tekens),
 * ≈ 306 bits. De PIN bestaat alleen in de teruggegeven [SecretBuffer]; de aanroeper wist hem.
 */
class PinGenerator(private val source: RandomSource = SecureRandomSource()) {

    /** Nieuwe buffer met een volledige PIN. */
    fun generate(): SecretBuffer {
        val buf = CharSecretBuffer(SecretBuffer.PIN_LENGTH)
        try {
            fill(buf)
        } catch (t: Throwable) {
            buf.wipe()
            throw t
        }
        return buf
    }

    /** Vult een lege [buffer] met capaciteit 63. */
    fun fill(buffer: SecretBuffer) {
        require(buffer.capacity == SecretBuffer.PIN_LENGTH && buffer.length == 0) { "verwacht een lege buffer van 63" }
        repeat(SecretBuffer.PIN_LENGTH) {
            val v = source.nextInt(Alphabet.SIZE)
            check(v in 0 until Alphabet.SIZE) { "randombron buiten bereik" }
            buffer.append(Alphabet.charAt(v))
        }
        check(isWellFormed(buffer)) { "gegenereerde PIN voldoet niet" }
    }

    companion object {
        /**
         * true als [pin] precies 63 tekens heeft, allemaal uit [Alphabet] en ASCII (bytes == tekens).
         */
        fun isWellFormed(pin: SecretBuffer): Boolean {
            if (pin.isWiped || pin.length != SecretBuffer.PIN_LENGTH) return false
            return pin.useChars { a ->
                var bad = 0
                for (c in a) {
                    bad = bad or (Alphabet.valueOf(c) ushr 31) or (if (c.code > 0x7f) 1 else 0)
                }
                bad == 0
            }
        }
    }
}
