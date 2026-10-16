package nl.icthorse.horsesafe.approval

import java.io.File
import java.nio.file.Files
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import nl.icthorse.horsesafe.crypto.X25519
import nl.icthorse.horsesafe.keystore.KeySlot
import nl.icthorse.horsesafe.net.DeviceApi
import nl.icthorse.horsesafe.net.DeviceKey
import nl.icthorse.horsesafe.pairing.DeviceRecord
import nl.icthorse.horsesafe.pairing.DeviceStore
import nl.icthorse.horsesafe.pairing.FakeFinger
import nl.icthorse.horsesafe.pairing.FakeKeys
import nl.icthorse.horsesafe.pairing.LocalState
import nl.icthorse.horsesafe.pairing.PairFixture
import nl.icthorse.horsesafe.ui.ApprovalServices
import nl.icthorse.horsesafe.ui.ApprovalViewModel
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Goedkeuringskaart: polling → kaart → goedkeuren/weigeren, met de echte ApprovalFlow boven nep-onderdelen. */
@OptIn(ExperimentalCoroutinesApi::class)
class ApprovalViewModelTest {
    private val dispatcher = StandardTestDispatcher()
    private lateinit var dir: File
    private val keys = FakeKeys()
    private val finger = FakeFinger()
    private lateinit var server: FakeApprovalServer
    private lateinit var flow: ApprovalFlow

    @Before fun setUp() {
        Dispatchers.setMain(dispatcher)
        dir = Files.createTempDirectory("hs-avm").toFile()
        keys.create(ByteArray(32), KeySlot.A)
        val skC = X25519.newPrivate(SecureRandom())
        val wrap = keys.wrapCipher(KeySlot.A)
        val ct = wrap.doFinal(skC)
        DeviceStore(dir).save(
            DeviceRecord(PairFixture.DEVICE_ID, LocalState.ACTIVE, "123456", "Fold", wrap.iv, ct,
                listOf(DeviceKey(PairFixture.KEY_ID, PairFixture.VAULT_ID, "Database")), 0, KeySlot.A),
        )
        server = FakeApprovalServer(keys, X25519.publicKey(skC))
        val now = (server.vector["created_at"] as Long) * 1000 + 10_000
        flow = ApprovalFlow(keys, finger, DeviceApi(server, clockSeconds = { now / 1000 }), DeviceStore(dir), {}, { now })
    }

    @After fun tearDown() {
        Dispatchers.resetMain()
        dir.deleteRecursively()
    }

    private fun TestScope.vm() = ApprovalViewModel(object : ApprovalServices {
        override val approvals = flow
    }, io = dispatcher)

    private fun TestScope.step() {
        advanceTimeBy(50)
        runCurrent()
    }

    @Test fun pollingToontKaartEnGoedkeurenLukt() = runTest(dispatcher) {
        val vm = vm()
        vm.setActive(true)
        step()
        val card = vm.ui.value.card
        assertNotNull(card)
        assertEquals(CardTrust.SIGNED, card!!.trust)
        assertTrue(finger.steps.isEmpty())
        vm.approve()
        step()
        assertTrue(vm.ui.value.resultOk)
        assertNull(vm.ui.value.card)
        assertEquals("approve", server.decisions.single()["decision"])
        // Hetzelfde verzoek komt niet opnieuw op de kaart.
        vm.dismiss()
        step()
        assertNull(vm.ui.value.card)
        vm.setActive(false)
    }

    @Test fun gemanipuleerdVerzoekToontNietVertrouwd() = runTest(dispatcher) {
        server.detail["created_at"] = (server.vector["created_at"] as Long) - 1
        val vm = vm()
        vm.setActive(true)
        step()
        val u = vm.ui.value
        assertEquals(CardTrust.SIG_INVALID, u.card!!.trust)
        assertTrue(u.untrusted)
        assertEquals(mapOf("decision" to "deny", "reason" to "sig_req_invalid"), server.decisions.single())
        vm.approve() // doet niets
        step()
        assertEquals(1, server.decisions.size)
        assertTrue(finger.steps.isEmpty())
        vm.setActive(false)
    }

    @Test fun weigerenEnIntrekken() = runTest(dispatcher) {
        val vm = vm()
        vm.setActive(true)
        step()
        vm.deny(revoke = true)
        step()
        assertEquals(mapOf("decision" to "deny_revoke"), server.decisions.single())
        assertTrue(vm.ui.value.result!!.contains("niet meer vertrouwd"))
        assertFalse(vm.ui.value.resultOk)
        vm.setActive(false)
    }

    @Test fun proofFoutToontNietVertrouwd() = runTest(dispatcher) {
        server.browser["label"] = "Ander apparaat"
        val vm = vm()
        vm.setActive(true)
        step()
        vm.approve()
        step()
        assertTrue(vm.ui.value.untrusted)
        assertTrue(vm.ui.value.result!!.startsWith(ApprovalViewModel.UNTRUSTED))
        assertEquals("browser_proof_invalid", server.decisions.single()["reason"])
        vm.setActive(false)
    }

    @Test fun nietActiefGeenPolling() = runTest(dispatcher) {
        val vm = vm()
        step()
        assertTrue(server.paths.isEmpty())
        vm.setActive(true)
        vm.setActive(false)
        step()
        assertNull(vm.ui.value.card)
    }
}
