package nl.icthorse.horsesafe.ui

import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.test.TestDispatcher
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import nl.icthorse.horsesafe.flow.ChangePinFlow
import nl.icthorse.horsesafe.flow.DefaultSetupMachine
import nl.icthorse.horsesafe.flow.EnvironmentProbe
import nl.icthorse.horsesafe.flow.FingerFlow
import nl.icthorse.horsesafe.flow.KeuringFlow
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.ReportFactory
import nl.icthorse.horsesafe.flow.SetupMachine
import nl.icthorse.horsesafe.flow.SetupMode
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.fake.CyclicSource
import nl.icthorse.horsesafe.flow.fake.FakeAttestationJudge
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.report.ReportStore
import nl.icthorse.horsesafe.secure.EnvReport
import nl.icthorse.horsesafe.secure.SecretRegistry
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyDiscovery
import nl.icthorse.horsesafe.yubikey.api.KeyLinkEvent
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * De ViewModel stuurt de echte [DefaultSetupMachine] en flows aan tegen de [FakeYubiKey] (geen echte
 * sleutel, geen Android). Controleert schermvolgorde, wissen bij onStop en dat geen PIN-fragment in de
 * Compose-state of in toString terechtkomt (kanarie).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ViewModelFlowTest {

    /** Alleen letters buiten 0-9a-f, zodat hex in rapporten nooit per toeval matcht. */
    private val sentinel = intArrayOf(9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 6, 7, 8, 9, 11)

    private lateinit var dispatcher: TestDispatcher
    private lateinit var dir: File

    private class FakeDiscovery : KeyDiscovery {
        val flow = MutableStateFlow<KeyLinkEvent>(KeyLinkEvent.None)
        override val events: StateFlow<KeyLinkEvent> = flow
        var started = 0
        override fun start(allowNfc: Boolean) { started++ }
        override fun stop() { flow.value = KeyLinkEvent.None }
    }

    private inner class Services : AppServices {
        val discovery = FakeDiscovery()
        override val appVersion = "0.3.0-Miller"
        override val isDebugBuild = true
        override val trust = TrustInfo("r", "a", 1, 1, null)
        override val inspector: InspectorOps = KeyProfiles.inspector()
        override val reportFactory: ReportFactory = KeyProfiles.reports()
        override val reports = ReportStore(dir)
        override fun createSetupMachine(profile: Profile, mode: SetupMode): SetupMachine =
            DefaultSetupMachine(profile, mode, inspector, FakeAttestationJudge, reportFactory, PinGenerator(CyclicSource(sentinel)))
        override fun createDiscovery(): KeyDiscovery = discovery
        override fun keuringFlow(env: EnvironmentProbe) = KeuringFlow(inspector, FakeAttestationJudge, reportFactory, env)
        override fun changePinFlow(profile: Profile, env: EnvironmentProbe) =
            ChangePinFlow(profile, inspector, reportFactory, PinGenerator(CyclicSource(sentinel.reversedArray())), env)
        override fun fingerFlow(env: EnvironmentProbe) = FingerFlow(inspector, reportFactory, env)
    }

    @Before fun setUp() {
        dispatcher = UnconfinedTestDispatcher()
        Dispatchers.setMain(dispatcher)
        dir = Files.createTempDirectory("hs-ui").toFile()
        SecretRegistry.clearForTest()
    }

    @After fun tearDown() {
        Dispatchers.resetMain()
        dir.deleteRecursively()
        SecretRegistry.clearForTest()
    }

    private fun vm(s: Services) = HorseSafeViewModel(s, dispatcher, dispatcher).also { it.onStart() }

    private fun checklist(vm: HorseSafeViewModel) {
        Texts.checklist.indices.forEach { vm.toggleChecklist(it) }
        vm.checklistDone()
    }

    /** Leest de PIN zoals Christian hem van M4 overschrijft (alleen in de test). */
    private fun readPaper(vm: HorseSafeViewModel): Pair<CharArray, CharArray> {
        val pin = CharArray(63)
        val checks = CharArray(9)
        for (g in 0 until GroupCheck.GROUPS) {
            vm.revealPress(g)
            vm.drawGroup(g) { chars, start, count, part ->
                when (part) {
                    0 -> System.arraycopy(chars, start, pin, g * 7, count)
                    1 -> System.arraycopy(chars, start, pin, g * 7 + 4, count)
                    else -> checks[g] = chars[start]
                }
            }
            vm.revealRelease()
        }
        return pin to checks
    }

    private fun windows(pin: CharArray): Set<String> = (0..pin.size - 7).map { String(pin, it, 7) }.toSet()

    private fun assertNoLeak(text: String, pin: CharArray) {
        assertTrue("PIN-fragment in UI-state", windows(pin).none { it in text })
    }

    @Test fun hoofdsleutelVolledigViaDeUi() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        val key = FakeYubiKey(KeyProfiles.bioFido574())
        vm.start(Purpose.SETUP_NEW, Profile.BIO_MAIN)
        assertEquals(Screen.M1_CHECKLIST, vm.ui.value.screen)
        checklist(vm)
        assertEquals(Screen.M2_CONNECT, vm.ui.value.screen)
        s.discovery.flow.value = KeyLinkEvent.Connected(key)
        advanceUntilIdle()
        assertEquals(Screen.M3_JUDGEMENT, vm.ui.value.screen)
        assertEquals(State.GateNewOk, vm.ui.value.machine)
        vm.judgementContinue()
        advanceUntilIdle()
        assertEquals(Screen.M4_REVEAL, vm.ui.value.screen)
        val (paper, checks) = readPaper(vm)
        assertEquals(9, vm.ui.value.reveal.seen.size)
        for (g in 0 until 9) assertEquals(GroupCheck.checkChar(paper, g * 7), checks[g])
        assertNoLeak(vm.ui.value.toString(), paper)

        vm.toCopyStep()
        assertEquals(Screen.M5_COPY, vm.ui.value.screen)
        vm.setCopyConfirmed(true)
        vm.copyDone()
        advanceUntilIdle()
        assertEquals(Screen.M6_RETYPE, vm.ui.value.screen)
        assertTrue(vm.ui.value.entry!!.groupCheckAvailable)
        paper.forEach { vm.key(it) }
        assertTrue(vm.ui.value.entry!!.complete)
        assertNoLeak(vm.ui.value.toString(), paper)
        vm.entrySubmit()
        advanceUntilIdle()
        assertEquals(Screen.M6B_IRREVERSIBLE, vm.ui.value.screen)
        assertTrue(key.pinEquals(paper))
        vm.confirmIrreversible() // zonder vinkje: niets
        advanceUntilIdle()
        assertEquals(Screen.M6B_IRREVERSIBLE, vm.ui.value.screen)
        vm.setIrreversibleTicked(true)
        vm.confirmIrreversible()
        advanceUntilIdle()
        assertEquals(Screen.M7_FINGERS, vm.ui.value.screen)
        assertEquals(63, key.minPinLength)
        vm.enrollFinger("R-wijs")
        advanceUntilIdle()
        vm.enrollFinger("L-wijs")
        advanceUntilIdle()
        assertEquals(2, vm.ui.value.fingers.size)
        vm.fingersDone()
        advanceUntilIdle()
        val u = vm.ui.value
        assertEquals(Screen.M10_REPORT, u.screen)
        assertTrue(u.finalReport)
        assertEquals(ReportKind.SETUP, u.report!!.kind)
        // Inrichting = nieuwe basis, geen vergelijking met een (andere) sleutel van hetzelfde profiel.
        assertNull(u.comparison)
        assertEquals(nl.icthorse.horsesafe.flow.Verdict.GREEN, u.report!!.checks.single { it.id == "vergelijking" }.verdict)
        assertFalse(u.report!!.comparedWithPrevious)
        // Het inrichtingsrapport is al vóór Afsluiten bewaard (basis voor de eerste keuring).
        assertEquals(1, s.reports.loadAll().reports.size)
        assertNoLeak(u.toString() + vm.toString(), paper)

        vm.quit()
        advanceUntilIdle()
        assertTrue(vm.ui.value.quit)
        assertEquals(1, s.reports.loadAll().reports.size)
        assertFalse(vm.ui.value.secretsTouched && !vm.ui.value.quit)
        paper.fill('\u0000')
    }

    @Test fun onStopTijdensTonenWistEnStopt() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.start(Purpose.SETUP_NEW, Profile.BIO_MAIN)
        checklist(vm)
        s.discovery.flow.value = KeyLinkEvent.Connected(FakeYubiKey(KeyProfiles.bioFido574()))
        vm.judgementContinue()
        advanceUntilIdle()
        assertEquals(Screen.M4_REVEAL, vm.ui.value.screen)
        vm.onStop()
        vm.onStart()
        advanceUntilIdle()
        val u = vm.ui.value
        assertEquals(Screen.M11_STOP, u.screen)
        assertEquals(Stop.RESTART_BEFORE_PIN, (u.machine as State.Stopped).stop)
        assertTrue((u.machine as State.Stopped).written.isEmpty())
        // na de stop tekent M4 niets meer
        var drawn = false
        vm.drawGroup(0) { _, _, _, _ -> drawn = true }
        assertFalse(drawn)
    }

    @Test fun omgevingsovertredingBlokkeertTonen() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.start(Purpose.SETUP_NEW, Profile.BIO_MAIN)
        checklist(vm)
        s.discovery.flow.value = KeyLinkEvent.Connected(FakeYubiKey(KeyProfiles.bioFido574()))
        vm.judgementContinue()
        advanceUntilIdle()
        vm.onEnvironment(EnvReport(listOf(Stop.ENV_ACCESSIBILITY), emptyList()))
        advanceUntilIdle()
        assertFalse(vm.revealAllowed())
        assertEquals(Screen.M11_STOP, vm.ui.value.screen)
        assertEquals(Stop.ENV_ACCESSIBILITY, (vm.ui.value.machine as State.Stopped).stop)
    }

    @Test fun focusverliesVerbergtDePin() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.start(Purpose.SETUP_NEW, Profile.BIO_MAIN)
        checklist(vm)
        s.discovery.flow.value = KeyLinkEvent.Connected(FakeYubiKey(KeyProfiles.bioFido574()))
        vm.judgementContinue()
        advanceUntilIdle()
        vm.revealPress(0)
        vm.setWindowVisible(false)
        assertNull(vm.ui.value.reveal.pressed)
        var drawn = false
        vm.drawGroup(0) { _, _, _, _ -> drawn = true }
        assertFalse(drawn)
    }

    @Test fun oefenenZonderSleutelSlaatNietsOp() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.choose(Purpose.PRACTICE)
        assertEquals(Screen.M8_PIN_ENTRY, vm.ui.value.screen)
        val pin = CharArray(63) { i -> nl.icthorse.horsesafe.pin.Alphabet.charAt((i * 5 + 1) % 29) }
        for (g in 0 until 9) {
            for (i in 0 until 7) vm.key(pin[g * 7 + i])
            vm.key(GroupCheck.checkChar(pin, g * 7))
        }
        assertTrue(vm.ui.value.entry!!.complete)
        assertNoLeak(vm.ui.value.toString(), pin)
        assertTrue(s.reports.loadAll().reports.isEmpty())
        vm.practiceAgain()
        assertEquals(0, vm.ui.value.entry!!.groupsDone)
        assertFalse(vm.ui.value.secretsTouched)
    }

    @Test fun oefenenOokGeblokkeerdBijOmgevingsovertreding() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.choose(Purpose.PRACTICE)
        vm.key('a'); vm.key('b')
        assertEquals(2, vm.ui.value.entry!!.typedInGroup)
        vm.onEnvironment(EnvReport(listOf(Stop.ENV_ACCESSIBILITY), emptyList()))
        assertNull("invoer gewist bij overtreding", vm.ui.value.entry)
        vm.key('c')
        assertNull(vm.ui.value.entry)
        vm.practiceAgain() // nieuw blok, maar toetsen worden geweigerd zolang de overtreding duurt
        vm.key('d')
        assertEquals(0, vm.ui.value.entry!!.typedInGroup)
        vm.onEnvironment(EnvReport(listOf(Stop.ENV_ADB), emptyList()))
        vm.entrySubmit()
        vm.practiceOnKey()
        assertEquals(Screen.M8_PIN_ENTRY, vm.ui.value.screen)
        assertFalse(vm.ui.value.secretsTouched)
    }

    @Test fun oefenenEchteControleDaarnaAlleenAfsluiten() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        val pin = CharArray(63) { i -> nl.icthorse.horsesafe.pin.Alphabet.charAt((i * 5 + 1) % 29) }
        val key = FakeYubiKey(KeyProfiles.bioFido574())
        key.preset(pin = pin, fingers = listOf("R-wijs", "L-wijs"), minLen = 63, alwaysUvOn = true)
        vm.choose(Purpose.PRACTICE)
        for (g in 0 until 9) {
            for (i in 0 until 7) vm.key(pin[g * 7 + i])
            vm.key(GroupCheck.checkChar(pin, g * 7))
        }
        vm.practiceOnKey()
        assertEquals(Screen.M2_CONNECT, vm.ui.value.screen)
        s.discovery.flow.value = KeyLinkEvent.Connected(key)
        advanceUntilIdle()
        val u = vm.ui.value
        assertNotNull(u.practiceKeyResult)
        assertEquals(Screen.M8_PIN_ENTRY, u.screen)
        assertNull("na F7b geen nieuwe invoer", u.entry)
        vm.practiceAgain()
        assertNull(vm.ui.value.entry)
        vm.onStop(); vm.onStart()
        assertNull("ook na onStart geen nieuwe invoer", vm.ui.value.entry)
        val tokensBefore = key.log.count { it.startsWith("pinToken") }
        vm.practiceOnKey()
        assertEquals(tokensBefore, key.log.count { it.startsWith("pinToken") })
        vm.quit()
        assertTrue(vm.ui.value.quit)
        pin.fill('\u0000')
    }

    @Test fun schermafbeeldingGeeftMeldingEnSluitGroep() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.start(Purpose.SETUP_NEW, Profile.BIO_MAIN)
        checklist(vm)
        s.discovery.flow.value = KeyLinkEvent.Connected(FakeYubiKey(KeyProfiles.bioFido574()))
        vm.judgementContinue()
        advanceUntilIdle()
        vm.revealPress(0)
        assertEquals(0, vm.ui.value.reveal.pressed)
        vm.onScreenCaptured()
        assertNull(vm.ui.value.reveal.pressed)
        assertNotNull(vm.ui.value.message)
    }

    @Test fun keurenZonderPinGeeftM9EnBewaartRapport() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        val key = FakeYubiKey(KeyProfiles.bioFido574())
        key.preset(pin = CharArray(63) { 'k' }, fingers = listOf("R-wijs", "L-wijs"), minLen = 63, alwaysUvOn = true)
        vm.choose(Purpose.KEURING_ZONDER_PIN)
        vm.pickProfile(Profile.BIO_MAIN)
        assertEquals(Screen.M2_CONNECT, vm.ui.value.screen)
        s.discovery.flow.value = KeyLinkEvent.Connected(key)
        advanceUntilIdle()
        val u = vm.ui.value
        assertEquals(Screen.M9_KEURING, u.screen)
        assertNotNull(u.report)
        assertEquals(ReportKind.KEURING_ZONDER_PIN, u.report!!.kind)
        assertFalse(u.comparison!!.hasBasis)
        assertFalse(u.secretsTouched)
        assertEquals(1, s.reports.loadAll().reports.size)
        assertTrue(key.writes().isEmpty())
        vm.backToStart()
        assertEquals(Screen.M0_START, vm.ui.value.screen)
    }

    @Test fun afbrekenNaPinGeeftAlleenAfsluiten() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.start(Purpose.SETUP_NEW, Profile.BIO_MAIN)
        checklist(vm)
        s.discovery.flow.value = KeyLinkEvent.Connected(FakeYubiKey(KeyProfiles.bioFido574()))
        vm.judgementContinue()
        advanceUntilIdle()
        vm.cancel()
        advanceUntilIdle()
        assertEquals(Screen.M11_STOP, vm.ui.value.screen)
        vm.backToStart() // mag niet meer: er was een PIN
        assertEquals(Screen.M11_STOP, vm.ui.value.screen)
        vm.quit()
        assertTrue(vm.ui.value.quit)
    }

    @Test fun registryWistOokDeViewModel() = runTest(dispatcher) {
        val s = Services()
        val vm = vm(s)
        vm.choose(Purpose.PRACTICE)
        vm.key('a'); vm.key('b')
        SecretRegistry.wipeAll()
        assertNull(vm.ui.value.entry)
        vm.key('c') // na het wissen wordt niets meer aangenomen
        assertNull(vm.ui.value.entry)
    }
}
