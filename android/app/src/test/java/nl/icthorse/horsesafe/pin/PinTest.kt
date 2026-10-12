package nl.icthorse.horsesafe.pin

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.nio.CharBuffer

class PinTest {
    /** Vaste, deterministische bron (xorshift) — alleen in de test. */
    private class SeededSource(seed: Long) : RandomSource {
        private var x = seed or 1L
        var calls = 0
        val bounds = mutableSetOf<Int>()
        override fun nextInt(bound: Int): Int {
            calls++; bounds += bound
            x = x xor (x shl 13); x = x xor (x ushr 7); x = x xor (x shl 17)
            return ((x ushr 1) % bound).toInt()
        }
    }

    @Test fun alfabet() {
        assertEquals("abcdefghjkmnpqrstuvwx23456789", Alphabet.CHARS)
        assertEquals(29, Alphabet.SIZE)
        Alphabet.CHARS.forEachIndexed { i, c -> assertEquals(i, Alphabet.valueOf(c)); assertEquals(c, Alphabet.charAt(i)) }
        "ilouyz01IOLABZ -_é\u0000".forEach { if (it !in Alphabet.CHARS) assertEquals(it.toString(), -1, Alphabet.valueOf(it)) }
        // Elke char (BMP) die niet in het alfabet zit → -1.
        for (code in 0..0xffff) {
            val c = code.toChar()
            assertEquals(Alphabet.CHARS.indexOf(c), Alphabet.valueOf(c))
        }
    }

    @Test fun lengteAlfabetEnBytes() {
        val gen = PinGenerator()
        repeat(200) {
            gen.generate().use { pin ->
                assertEquals(63, pin.length)
                assertTrue(PinGenerator.isWellFormed(pin))
                pin.useChars { a ->
                    assertEquals(63, a.size)
                    a.forEach { c -> assertTrue(c in Alphabet.CHARS) }
                    val bytes = Charsets.UTF_8.encode(CharBuffer.wrap(a))
                    assertEquals("bytes == tekens", 63, bytes.remaining())
                    for (i in 0 until 63) assertEquals(a[i].code.toByte(), bytes.get(i))
                }
            }
        }
    }

    @Test fun geinjecteerdeBronEnVasteSeed() {
        val s1 = SeededSource(42)
        val s2 = SeededSource(42)
        val a = PinGenerator(s1).generate()
        val b = PinGenerator(s2).generate()
        assertEquals(63, s1.calls)
        assertEquals(setOf(29), s1.bounds)
        assertTrue("zelfde seed → zelfde PIN", PinCompare.equal(a, b))
        val c = PinGenerator(SeededSource(4242)).generate()
        assertFalse(PinCompare.equal(a, c))
        // Afbeelding waarde → teken is precies Alphabet.charAt.
        val fixed = PinGenerator { 28 }.generate()
        fixed.useChars { arr -> arr.forEach { assertEquals('9', it) } }
        listOf(a, b, c, fixed).forEach { it.wipe() }
    }

    @Test fun bronBuitenBereikWordtGeweigerd() {
        for (bad in listOf(-1, 29, 1000)) {
            try {
                PinGenerator { bad }.generate()
                fail("verwacht IllegalStateException voor $bad")
            } catch (e: IllegalStateException) {
                // ok
            }
        }
    }

    @Test fun verdelingMetVasteSeed() {
        val counts = IntArray(29)
        val gen = PinGenerator(SeededSource(0x5eed))
        val pins = 2000
        repeat(pins) { gen.generate().use { p -> p.useChars { a -> a.forEach { counts[Alphabet.valueOf(it)]++ } } } }
        val n = pins * 63.0
        val e = n / 29
        val chi2 = counts.sumOf { (it - e) * (it - e) / e }
        // df = 28; p = 1e-6 ligt bij ≈ 75.
        assertTrue("chi² $chi2", chi2 < 75)
    }

    @Test fun verdelingSecureRandom() {
        val counts = IntArray(29)
        val gen = PinGenerator()
        repeat(2000) { gen.generate().use { p -> p.useChars { a -> a.forEach { counts[Alphabet.valueOf(it)]++ } } } }
        val e = 2000 * 63.0 / 29
        val chi2 = counts.sumOf { (it - e) * (it - e) / e }
        assertTrue("chi² $chi2", chi2 < 75)
    }

    @Test fun secretBufferGedrag() {
        val b = CharSecretBuffer()
        assertEquals(63, b.capacity)
        assertEquals(SecretBuffer.HIDDEN, b.toString())
        "abc".forEach { b.append(it) }
        assertEquals(3, b.length)
        assertEquals('c', b[2])
        b.removeLast()
        assertEquals(2, b.length)
        b.useChars { assertEquals(2, it.size); assertEquals('a', it[0]) }
        assertEquals("[verborgen]", "$b")
        val other = CharSecretBuffer().apply { append('a'); append('b') }
        assertNotEquals("equals is identiteit", b, other)
        assertTrue(PinCompare.equal(b, other))
        b.wipe()
        b.wipe() // idempotent
        assertTrue(b.isWiped)
        assertEquals(0, b.length)
        listOf<() -> Unit>({ b.append('x') }, { b[0] }, { b.useChars { } }, { b.removeLast() }).forEach {
            try { it(); fail("verwacht IllegalStateException") } catch (e: IllegalStateException) { }
        }
        val full = CharSecretBuffer(2).apply { append('a'); append('b') }
        try { full.append('c'); fail() } catch (e: IllegalStateException) { }
    }

    @Test fun useCharsWistTijdelijkeKopie() {
        val b = CharSecretBuffer().apply { "geheim".forEach { append(it) } }
        var leaked: CharArray? = null
        b.useChars { leaked = it }
        assertTrue("kopie gewist na blok", leaked!!.all { it == '\u0000' })
        // Volle buffer: de eigen array wordt geleend en bij wipe overschreven.
        val full = PinGenerator().generate()
        var arr: CharArray? = null
        full.useChars { arr = it }
        assertTrue(arr!!.any { it != '\u0000' })
        full.wipe()
        assertTrue(arr!!.all { it == '\u0000' })
    }

    @Test fun pinCompare() {
        val g = PinGenerator()
        val a = g.generate()
        val copy = CharSecretBuffer().also { c -> a.useChars { arr -> arr.forEach { c.append(it) } } }
        assertTrue(PinCompare.equal(a, copy))
        // Eén teken anders op elke positie.
        for (i in 0 until 63) {
            val d = CharSecretBuffer()
            a.useChars { arr -> arr.forEachIndexed { j, ch -> d.append(if (j == i) (if (ch == 'a') 'b' else 'a') else ch) } }
            assertFalse(PinCompare.equal(a, d))
            d.wipe()
        }
        val shorter = CharSecretBuffer().also { c -> a.useChars { arr -> arr.take(62).forEach { c.append(it) } } }
        assertFalse(PinCompare.equal(a, shorter))
        assertFalse(PinCompare.equal(shorter, a))
        assertTrue(PinCompare.equal(CharSecretBuffer(), CharSecretBuffer()))
        assertTrue(PinCompare.equal(charArrayOf('a', 'b'), charArrayOf('a', 'b')))
        assertFalse(PinCompare.equal(charArrayOf('a', 'b'), charArrayOf('a', 'c')))
        assertFalse(PinCompare.equal(charArrayOf('a'), charArrayOf('a', '\u0000')))
    }

    /** Constante tijd: bij een verschil op positie 0 worden toch alle posities gelezen. */
    @Test fun pinCompareLeestAllePosities() {
        class Counting(val inner: SecretBuffer) : SecretBuffer by inner {
            var reads = 0
            override fun get(index: Int): Char { reads++; return inner[index] }
            override fun toString() = SecretBuffer.HIDDEN
        }
        val a = Counting(CharSecretBuffer().apply { repeat(63) { append('a') } })
        val b = Counting(CharSecretBuffer().apply { repeat(63) { append(if (it == 0) 'b' else 'a') } })
        assertFalse(PinCompare.equal(a, b))
        assertEquals(63, a.reads)
        assertEquals(63, b.reads)
    }
}
