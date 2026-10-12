package nl.icthorse.horsesafe.pin

/**
 * Indeling van de PIN in [GROUPS] groepen van [GROUP_SIZE] tekens, elk met een controleteken
 * `Σ(i+1)·v_i mod 29` (i = 0..6). Omdat 29 priem is en de gewichten 1..7 niet 0 mod 29 zijn, vangt dit
 * elke enkele substitutie en elke omwisseling van twee verschillende buren binnen een groep.
 *
 * Het controleteken hoort NIET bij de PIN (de PIN is 63 tekens); het staat alleen op het papier en
 * wordt bij M8 per groep meegetypt. Een fout controleteken kost geen poging op de sleutel.
 * Controletekens zijn afgeleid van de PIN en dus ook geheim: alleen als Char/CharArray, nooit String.
 */
object GroupCheck {
    const val GROUPS: Int = 9
    const val GROUP_SIZE: Int = 7

    init {
        check(GROUPS * GROUP_SIZE == SecretBuffer.PIN_LENGTH)
    }

    /** Controleteken over [GROUP_SIZE] tekens van [chars] vanaf [offset]. */
    fun checkChar(chars: CharArray, offset: Int = 0): Char {
        require(offset >= 0 && offset + GROUP_SIZE <= chars.size) { "groep valt buiten de invoer" }
        var sum = 0
        var invalid = 0
        for (i in 0 until GROUP_SIZE) {
            val v = Alphabet.valueOf(chars[offset + i])
            invalid = invalid or (v ushr 31) // 1 als v == -1
            sum += (i + 1) * v
        }
        require(invalid == 0) { "teken buiten het alfabet" }
        return Alphabet.charAt(sum % Alphabet.SIZE)
    }

    /** Controleteken van groep [group] (0-based) van een volledige PIN. */
    fun checkChar(pin: SecretBuffer, group: Int): Char {
        require(group in 0 until GROUPS) { "groep bestaat niet" }
        require(pin.length == SecretBuffer.PIN_LENGTH) { "PIN niet compleet" }
        return pin.useChars { checkChar(it, group * GROUP_SIZE) }
    }

    /** Alle 9 controletekens van [pin], voor M4. De aanroeper wist het resultaat (`fill('\u0000')`). */
    fun checkChars(pin: SecretBuffer): CharArray {
        require(pin.length == SecretBuffer.PIN_LENGTH) { "PIN niet compleet" }
        return pin.useChars { a -> CharArray(GROUPS) { g -> checkChar(a, g * GROUP_SIZE) } }
    }

    /**
     * Klopt één getypte groep (7 tekens vanaf [offset]) met het getypte controleteken [check]?
     * false (geen exception) bij een teken buiten het alfabet, zodat M8 "groep N klopt niet" kan tonen.
     */
    fun verifyGroup(chars: CharArray, offset: Int, check: Char): Boolean {
        if (offset < 0 || offset + GROUP_SIZE > chars.size) return false
        var bad = 0
        for (i in 0 until GROUP_SIZE) bad = bad or (Alphabet.valueOf(chars[offset + i]) ushr 31)
        val checkValue = Alphabet.valueOf(check)
        if (bad != 0 || checkValue < 0) return false
        return checkChar(chars, offset) == check
    }

    /**
     * Controleert een volledige PIN tegen de 9 getypte controletekens.
     * @return 1-based nummers van de groepen die niet kloppen (leeg = alles groen).
     */
    fun badGroups(pin: SecretBuffer, checks: CharArray): List<Int> {
        require(checks.size == GROUPS) { "verwacht $GROUPS controletekens" }
        if (pin.length != SecretBuffer.PIN_LENGTH) return (1..GROUPS).toList()
        return pin.useChars { a -> (0 until GROUPS).filterNot { g -> verifyGroup(a, g * GROUP_SIZE, checks[g]) }.map { it + 1 } }
    }
}
