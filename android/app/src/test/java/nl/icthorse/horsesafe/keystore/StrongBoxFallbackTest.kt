package nl.icthorse.horsesafe.keystore

import java.security.InvalidAlgorithmParameterException
import java.security.ProviderException
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

/**
 * StrongBox eerst, terugval op de TEE (§13.2). StrongBoxUnavailableException is een subklasse van
 * ProviderException (Android-stub, op de JVM niet te maken); een kale ProviderException moet ook terugvallen.
 */
class StrongBoxFallbackTest {
    @Test fun strongBoxLuktGeenTerugval() {
        val calls = mutableListOf<Boolean>()
        assertEquals("sb", StrongBoxFallback.generate { sb -> calls += sb; if (sb) "sb" else "tee" })
        assertEquals(listOf(true), calls)
    }

    @Test fun providerExceptionBijStrongBoxValtTerugOpTee() {
        val calls = mutableListOf<Boolean>()
        val r = StrongBoxFallback.generate { sb ->
            calls += sb
            if (sb) throw ProviderException("Keystore key generation failed") else "tee"
        }
        assertEquals("tee", r)
        assertEquals(listOf(true, false), calls)
    }

    @Test fun foutBijTeeGaatDoor() {
        val calls = mutableListOf<Boolean>()
        try {
            StrongBoxFallback.generate<String> { sb ->
                calls += sb
                throw ProviderException(if (sb) "strongbox" else "tee")
            }
            fail()
        } catch (e: ProviderException) {
            assertEquals("tee", e.message)
        }
        assertEquals(listOf(true, false), calls)
    }

    @Test fun andereFoutBijStrongBoxGeenTerugval() {
        val calls = mutableListOf<Boolean>()
        try {
            StrongBoxFallback.generate<String> { sb ->
                calls += sb
                throw InvalidAlgorithmParameterException("spec")
            }
            fail()
        } catch (e: InvalidAlgorithmParameterException) {
            // verwacht: alleen ProviderException (en subklassen) leidt tot terugval
        }
        assertEquals(listOf(true), calls)
    }
}
