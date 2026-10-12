package nl.icthorse.horsesafe.pin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Random

class GroupCheckTest {
    private fun ref(g: CharArray): Char =
        Alphabet.CHARS[(0 until 7).sumOf { (it + 1) * Alphabet.CHARS.indexOf(g[it]) } % 29]

    private fun sample(n: Int, seed: Long): List<CharArray> {
        val r = Random(seed)
        return List(n) { CharArray(7) { Alphabet.CHARS[r.nextInt(29)] } }
    }

    @Test fun formule() {
        assertEquals(9, GroupCheck.GROUPS)
        assertEquals(7, GroupCheck.GROUP_SIZE)
        assertEquals('a', GroupCheck.checkChar("aaaaaaa".toCharArray()))
        // b=1: Σ(i+1) = 28 → '9'
        assertEquals('9', GroupCheck.checkChar("bbbbbbb".toCharArray()))
        sample(5000, 1).forEach { assertEquals(ref(it), GroupCheck.checkChar(it)) }
    }

    /** Wiskundig uitputtend: elke positie × elke afwijking d ≠ 0 verandert de som mod 29. */
    @Test fun enkeleSubstitutieAlgebraisch() {
        for (i in 0 until 7) for (d in 1 until 29) assertNotEquals(0, (i + 1) * d % 29)
    }

    /** Uitputtend over een steekproef: elke positie, elk ander teken → ander controleteken. */
    @Test fun elkeEnkeleSubstitutieWordtGevangen() {
        var tried = 0
        sample(1500, 2).forEach { g ->
            val check = GroupCheck.checkChar(g)
            for (i in 0 until 7) for (c in Alphabet.CHARS) {
                if (c == g[i]) continue
                val m = g.copyOf().also { it[i] = c }
                assertNotEquals(check, GroupCheck.checkChar(m))
                assertFalse(GroupCheck.verifyGroup(m, 0, check))
                tried++
            }
        }
        assertEquals(1500 * 7 * 28, tried)
    }

    /** Uitputtend over een steekproef én over alle tekenparen: elke buurverwisseling van ongelijke tekens. */
    @Test fun elkeBuurverwisselingWordtGevangen() {
        sample(1500, 3).forEach { g ->
            val check = GroupCheck.checkChar(g)
            for (i in 0 until 6) {
                if (g[i] == g[i + 1]) continue
                val m = g.copyOf().also { it[i] = g[i + 1]; it[i + 1] = g[i] }
                assertNotEquals(check, GroupCheck.checkChar(m))
            }
        }
        val base = "abcdefg".toCharArray()
        for (i in 0 until 6) for (x in Alphabet.CHARS) for (y in Alphabet.CHARS) {
            if (x == y) continue
            val g = base.copyOf().also { it[i] = x; it[i + 1] = y }
            val s = g.copyOf().also { it[i] = y; it[i + 1] = x }
            assertNotEquals(GroupCheck.checkChar(g), GroupCheck.checkChar(s))
        }
    }

    @Test fun verifyGroupEnBadGroups() {
        val pin = PinGenerator().generate()
        val checks = GroupCheck.checkChars(pin)
        assertEquals(9, checks.size)
        assertEquals(emptyList<Int>(), GroupCheck.badGroups(pin, checks))
        pin.useChars { a -> for (g in 0 until 9) assertTrue(GroupCheck.verifyGroup(a, g * 7, checks[g])) }
        val wrong = checks.copyOf().also { it[4] = if (it[4] == 'a') 'b' else 'a' }
        assertEquals(listOf(5), GroupCheck.badGroups(pin, wrong))
        // Teken buiten het alfabet → false, geen exception.
        assertFalse(GroupCheck.verifyGroup("abcdef1".toCharArray(), 0, 'a'))
        assertFalse(GroupCheck.verifyGroup("abcdefg".toCharArray(), 0, 'o'))
        assertFalse(GroupCheck.verifyGroup("abc".toCharArray(), 0, 'a'))
        assertEquals(pin.useChars { GroupCheck.checkChar(it, 14) }, GroupCheck.checkChar(pin, 2))
        checks.fill('\u0000')
        pin.wipe()
    }
}
