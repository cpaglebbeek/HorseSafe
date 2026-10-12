package nl.icthorse.horsesafe.secure

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import nl.icthorse.horsesafe.pin.CharSecretBuffer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class SecretRegistryTest {

    @Before fun setUp() = SecretRegistry.clearForTest()

    @After fun tearDown() {
        SecretRegistry.clearForTest()
        ProcessEnd.killer = { android.os.Process.killProcess(android.os.Process.myPid()) }
    }

    @Test fun wipeAllWistElkeBufferOokNaEenFout() {
        val a = CharSecretBuffer().apply { append('k') }
        val b = CharSecretBuffer().apply { append('m') }
        SecretRegistry.register { a.wipe() }
        SecretRegistry.register { throw IllegalStateException("boem") }
        SecretRegistry.register { b.wipe() }
        SecretRegistry.wipeAll()
        assertTrue(a.isWiped)
        assertTrue(b.isWiped)
    }

    @Test fun afmeldenWerkt() {
        var n = 0
        val h = SecretRegistry.register { n++ }
        h.close()
        SecretRegistry.wipeAll()
        assertEquals(0, n)
        assertEquals(0, SecretRegistry.size())
    }

    @Test fun processEndWistEerstEnDoodtDan() {
        val order = mutableListOf<String>()
        SecretRegistry.register { order += "wis" }
        ProcessEnd.killer = { order += "kill" }
        ProcessEnd.end(null)
        assertEquals(listOf("wis", "kill"), order)
    }

    @Test fun crashGuardWistDoodtEnSchrijftNiets() {
        val buf = CharSecretBuffer().apply { "geheim".forEach { append(it) } }
        SecretRegistry.register { buf.wipe() }
        var killed = false
        val err = ByteArrayOutputStream()
        val out = ByteArrayOutputStream()
        val oldErr = System.err
        val oldOut = System.out
        System.setErr(PrintStream(err, true))
        System.setOut(PrintStream(out, true))
        try {
            val g = CrashGuard.forTest(kill = { killed = true }, stepName = { "M6" })
            g.uncaughtException(Thread.currentThread(), IllegalArgumentException("PIN=kanarie123"))
        } finally {
            System.setErr(oldErr)
            System.setOut(oldOut)
        }
        assertTrue(killed)
        assertTrue(buf.isWiped)
        assertEquals("", err.toString() + out.toString())
        val info = CrashGuard.lastCrash!!
        assertEquals("IllegalArgumentException", info.type)
        assertEquals("M6", info.step)
        assertFalse(info.toString().contains("kanarie"))
    }

    @Test fun crashGuardDoodtOokAlsStapnaamFaalt() {
        var killed = false
        CrashGuard.forTest(kill = { killed = true }, stepName = { error("x") }).uncaughtException(Thread.currentThread(), RuntimeException())
        assertTrue(killed)
    }
}
