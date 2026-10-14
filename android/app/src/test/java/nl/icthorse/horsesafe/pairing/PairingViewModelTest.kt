package nl.icthorse.horsesafe.pairing

import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import nl.icthorse.horsesafe.biometric.BioAvailability
import nl.icthorse.horsesafe.net.DeviceApi
import nl.icthorse.horsesafe.ui.PairStep
import nl.icthorse.horsesafe.ui.PairingServices
import nl.icthorse.horsesafe.ui.PairingViewModel
import nl.icthorse.horsesafe.ui.Screen
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Schermovergangen M14-M19 met de echte PairingFlow boven nep-onderdelen. */
@OptIn(ExperimentalCoroutinesApi::class)
class PairingViewModelTest {
    private val dispatcher = StandardTestDispatcher()
    private lateinit var dir: File

    @Before fun setUp() {
        Dispatchers.setMain(dispatcher)
        dir = Files.createTempDirectory("hs-pvm").toFile()
    }

    @After fun tearDown() {
        Dispatchers.resetMain()
        dir.deleteRecursively()
    }

    private class Svc(override val flow: PairingFlow, var bio: BioAvailability = BioAvailability.OK) : PairingServices {
        override fun bioAvailability() = bio
        override fun deviceInfo() = DeviceInfo("Galaxy Z Fold6", "SM-F956B", "0.3.4-Miller")
    }

    private fun TestScope.vm(svc: Svc) = PairingViewModel(svc, io = dispatcher)

    private fun services(keys: FakeKeys = FakeKeys(), finger: FakeFinger = FakeFinger()): Pair<Svc, FakeServer> {
        val server = FakeServer(keys).also { it.activeAfter = 1 }
        val flow = PairingFlow(keys, finger, DeviceApi(server), DeviceStore(dir))
        return Svc(flow) to server
    }

    @Test fun zonderSterkeVingerBlokkeert() = runTest(dispatcher) {
        val (svc, _) = services()
        svc.bio = BioAvailability.NONE_ENROLLED
        val vm = vm(svc)
        vm.open()
        assertEquals(PairStep.BIO_BLOCKED, vm.ui.value.step)
        assertEquals(Screen.M18_BIO_REQUIRED, vm.ui.value.step.screen)
        svc.bio = BioAvailability.OK
        vm.recheck()
        assertEquals(PairStep.INTRO, vm.ui.value.step)
    }

    @Test fun volledigeKoppeling() = runTest(dispatcher) {
        val (svc, _) = services()
        val vm = vm(svc)
        vm.open()
        assertEquals(PairStep.INTRO, vm.ui.value.step)
        vm.startScan()
        assertEquals(PairStep.SCAN, vm.ui.value.step)
        vm.onQr("https://example.org")
        assertEquals(PairStep.SCAN, vm.ui.value.step)
        assertNotNull(vm.ui.value.message)
        vm.onQr(PairFixture.qrText())
        assertEquals(PairStep.WORKING, vm.ui.value.step)
        advanceUntilIdle()
        val u = vm.ui.value
        assertEquals(PairStep.DONE, u.step)
        assertTrue(u.active)
        assertEquals(1, u.keys.size)
        assertTrue(Regex("^[0-9]{6}$").matches(u.sas!!))
        assertFalse("UI-staat zonder geheim", u.toString().contains(PairFixture.qrText().substringAfter('.')))
        vm.trial(u.keys.single())
        advanceUntilIdle()
        assertTrue(vm.ui.value.trialResult!!.startsWith("Kopie klopt"))
    }

    @Test fun annulerenBijVingerToontMelding() = runTest(dispatcher) {
        val (svc, _) = services(finger = FakeFinger(cancelAt = FingerStep.SIGN))
        val vm = vm(svc)
        vm.open()
        vm.startScan()
        vm.onQr(PairFixture.qrText())
        advanceUntilIdle()
        assertEquals(PairStep.INTRO, vm.ui.value.step)
        assertNotNull(vm.ui.value.error)
        assertNull(svc.flow.current())
    }

    @Test fun gewijzigdeVingerafdrukGeeftM19() = runTest(dispatcher) {
        val keys = FakeKeys()
        val (svc, _) = services(keys = keys)
        val vm = vm(svc)
        vm.open()
        vm.startScan()
        vm.onQr(PairFixture.qrText())
        advanceUntilIdle()
        assertEquals(PairStep.DONE, vm.ui.value.step)
        keys.invalid = true
        vm.open()
        advanceUntilIdle()
        assertEquals(PairStep.REPAIR, vm.ui.value.step)
        assertNull(svc.flow.current())
        vm.restart()
        assertEquals(PairStep.INTRO, vm.ui.value.step)
    }

    @Test fun bestaandeKoppelingVraagtBevestiging() = runTest(dispatcher) {
        val (svc, _) = services()
        val vm = vm(svc)
        vm.open()
        vm.startScan()
        vm.onQr(PairFixture.qrText())
        advanceUntilIdle()
        vm.startScan()
        assertTrue(vm.ui.value.confirmReplace)
        assertEquals(PairStep.INTRO, vm.ui.value.step)
        vm.startScan()
        assertEquals(PairStep.SCAN, vm.ui.value.step)
    }

    @Test fun status401TijdensWachtenToontMeldingEnWistNiets() = runTest(dispatcher) {
        val keys = FakeKeys()
        val (svc, server) = services(keys = keys)
        server.activeAfter = 99
        val vm = vm(svc)
        vm.open()
        vm.startScan()
        server.statusError = 401
        vm.onQr(PairFixture.qrText())
        advanceUntilIdle()
        val u = vm.ui.value
        assertEquals(PairStep.SAS, u.step)
        assertNotNull(u.sas)
        assertTrue(u.error!!, u.error!!.contains("niets gewist"))
        assertNotNull(svc.flow.current())
        assertTrue(keys.anyPresent())
    }
}
