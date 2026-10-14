package nl.icthorse.horsesafe.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class B64uTest {
    @Test fun rondgang() {
        for (n in 0..40) {
            val b = ByteArray(n) { (it * 37 + 5).toByte() }
            val s = B64u.encode(b)
            assertEquals(-1, s.indexOf('='))
            assertArrayEquals(b, B64u.decode(s))
        }
    }

    @Test fun strikt() {
        listOf("AA==", "A", "AB", "a+b/", "AA AA", "AAA\n", "AAB").forEach { bad ->
            try {
                B64u.decode(bad)
                fail("geaccepteerd: $bad")
            } catch (e: IllegalArgumentException) {
                // goed
            }
        }
        try {
            B64u.decode(B64u.encode(ByteArray(15)), 16)
            fail("verkeerde lengte geaccepteerd")
        } catch (e: IllegalArgumentException) {
            // goed
        }
    }
}
