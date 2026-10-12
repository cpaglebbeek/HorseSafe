package nl.icthorse.horsesafe.yubikey.transport

import com.yubico.yubikit.core.Transport as YkTransport
import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.util.Callback
import com.yubico.yubikit.core.util.Result
import java.io.IOException
import java.util.concurrent.Executors
import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.yubikey.FakeAuthenticator
import nl.icthorse.horsesafe.yubikey.FakeHidConnection
import nl.icthorse.horsesafe.yubikey.NestedConnectionError
import nl.icthorse.horsesafe.yubikey.TestSecret
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.Transport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** [YubiKeyLink] + [DeviceConnectionRunner] op een nep-`YubiKeyDevice` (zoals yubikit: callback op eigen thread). */
class YubiKeyLinkTest {

    private class FakeDevice(private val fake: FakeAuthenticator) : YubiKeyDevice {
        val executor = Executors.newSingleThreadExecutor()
        var opened = 0
        var fail = false
        var callbackThread: Thread? = null

        override fun getTransport(): YkTransport = YkTransport.USB
        override fun supportsConnection(connectionType: Class<out YubiKeyConnection>): Boolean = connectionType == FidoConnection::class.java

        override fun <T : YubiKeyConnection> requestConnection(connectionType: Class<T>, callback: Callback<Result<T, IOException>>) {
            executor.submit {
                callbackThread = Thread.currentThread()
                if (fail) {
                    callback.invoke(Result.failure(IOException("weg")))
                    return@submit
                }
                opened++
                val hid = FakeHidConnection(fake::handle)
                @Suppress("UNCHECKED_CAST")
                callback.invoke(Result.success(hid as T))
            }
        }

        override fun <T : YubiKeyConnection> openConnection(connectionType: Class<T>): T = throw UnsupportedOperationException()
    }

    private val pin = "abcdefghjkmnpqrstuvwx23456789abcdefghjkmnpqrstuvwx23456789abcde"

    @Test
    fun elkeMethodeEenEigenVerbindingOpDeYubikitThread() = runBlocking {
        val fake = FakeAuthenticator().apply { options["clientPin"] = true }
        val dev = FakeDevice(fake)
        val link = YubiKeyLink(Transport.USB, DeviceConnectionRunner(dev) { false })
        link.readRawInfo()
        val info = link.ctap { freshInfo() }
        assertEquals(2, dev.opened)
        assertNotEquals(Thread.currentThread(), dev.callbackThread)
        assertEquals("10111213-1415-1617-1819-1a1b1c1d1e1f", info.aaguid.uuid)
    }

    @Test
    fun tokenNaDeFaseGewistEnOnbruikbaar() = runBlocking {
        val fake = FakeAuthenticator().apply { options["clientPin"] = true }
        val link = YubiKeyLink(Transport.USB, DeviceConnectionRunner(FakeDevice(fake)) { false })
        val leaked: AuthToken = link.ctap { pin.pinToken(TestSecret(this@YubiKeyLinkTest.pin), Permission.CM) }
        assertTrue(leaked.isWiped)
        try {
            link.ctap { credMgmt.metadata(leaked) }
            fail()
        } catch (e: KeyError.TokenInvalid) {
        }
    }

    @Test
    fun genesteVerbindingWordtGeweigerd() = runBlocking {
        val link = YubiKeyLink(Transport.USB, DeviceConnectionRunner(FakeDevice(FakeAuthenticator())) { false })
        try {
            link.ctap { link.readRawInfo() }
            fail()
        } catch (e: NestedConnectionError) {
        }
        // Daarna werkt de link weer.
        link.readRawInfo()
        Unit
    }

    @Test
    fun verbindingsfoutNaLoskoppelenIsDisconnected() = runBlocking {
        val dev = FakeDevice(FakeAuthenticator()).apply { fail = true }
        var gone = false
        var lost = 0
        val link = YubiKeyLink(Transport.USB, DeviceConnectionRunner(dev) { gone }) { lost++ }
        try {
            link.readRawInfo(); fail()
        } catch (e: KeyError.Io) {
            assertTrue(link.isConnected.value)
        }
        gone = true
        try {
            link.readRawInfo(); fail()
        } catch (e: KeyError.Disconnected) {
        }
        assertFalse(link.isConnected.value)
        assertEquals(1, lost)
        try {
            link.ctap { freshInfo() }; fail()
        } catch (e: KeyError.Disconnected) {
        }
    }
}
