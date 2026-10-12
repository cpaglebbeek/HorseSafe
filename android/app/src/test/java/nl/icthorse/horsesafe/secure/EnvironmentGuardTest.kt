package nl.icthorse.horsesafe.secure

import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EnvironmentGuardTest {

    private val clean = EnvSnapshot(
        adbEnabled = false, accessibilityNotAllowed = 0, inMultiWindow = false, inPictureInPicture = false,
        onNonDefaultDisplay = false, deskMode = false, samsungDex = null, presentationDisplays = 0, screenRecording = false,
    )

    private val release = EnvironmentGuard(adbIsStop = true)
    private val debug = EnvironmentGuard(adbIsStop = false)

    @Test fun schoneOmgevingBlokkeertNiets() {
        val r = release.evaluate(clean)
        assertTrue(r.violations.isEmpty())
        assertFalse(r.blocksSecrets)
    }

    @Test fun adbIsStopInReleaseEnWaarschuwingInDebug() {
        val s = clean.copy(adbEnabled = true)
        assertEquals(listOf(Stop.ENV_ADB), release.evaluate(s).violations)
        val d = debug.evaluate(s)
        assertTrue(d.violations.isEmpty())
        assertEquals(Verdict.ORANGE, d.warnings.single { it.id == EnvironmentGuard.ID_ADB }.verdict)
    }

    @Test fun draadloosAdbEnOntwikkelaarsoptiesZijnStopInRelease() {
        assertEquals(listOf(Stop.ENV_ADB), release.evaluate(clean.copy(adbWifiEnabled = true)).violations)
        assertEquals(listOf(Stop.ENV_ADB), release.evaluate(clean.copy(developerOptions = true)).violations)
        assertEquals(listOf(Stop.ENV_ADB), release.evaluate(clean.copy(adbEnabled = true, adbWifiEnabled = true, developerOptions = true)).violations)
        val d = debug.evaluate(clean.copy(developerOptions = true))
        assertTrue(d.violations.isEmpty())
        assertEquals(Verdict.ORANGE, d.warnings.single { it.id == EnvironmentGuard.ID_ADB }.verdict)
        assertEquals("adb_wifi_enabled", EnvironmentGuard.ADB_WIFI_ENABLED)
    }

    @Test fun toegankelijkheidsdienstBuitenAllowlistIsStop() {
        assertEquals(listOf(Stop.ENV_ACCESSIBILITY), release.evaluate(clean.copy(accessibilityNotAllowed = 1)).violations)
    }

    @Test fun multiWindowPipDisplayDexEnOpname() {
        assertEquals(listOf(Stop.ENV_MULTI_WINDOW), release.evaluate(clean.copy(inMultiWindow = true)).violations)
        assertEquals(listOf(Stop.ENV_MULTI_WINDOW), release.evaluate(clean.copy(inPictureInPicture = true)).violations)
        assertEquals(listOf(Stop.ENV_EXTERNAL_DISPLAY), release.evaluate(clean.copy(onNonDefaultDisplay = true)).violations)
        assertEquals(listOf(Stop.ENV_EXTERNAL_DISPLAY), release.evaluate(clean.copy(deskMode = true)).violations)
        assertEquals(listOf(Stop.ENV_EXTERNAL_DISPLAY), release.evaluate(clean.copy(samsungDex = true)).violations)
        assertTrue(release.evaluate(clean.copy(samsungDex = false)).violations.isEmpty())
        assertEquals(listOf(Stop.ENV_SCREEN_RECORDING), release.evaluate(clean.copy(screenRecording = true)).violations)
    }

    @Test fun extraPresentatieschermIsAlleenMelding() {
        val r = release.evaluate(clean.copy(presentationDisplays = 1))
        assertTrue(r.violations.isEmpty())
        assertEquals(Verdict.ORANGE, r.warnings.single { it.id == EnvironmentGuard.ID_DISPLAY }.verdict)
    }

    @Test fun meerdereOvertredingenZonderDubbelen() {
        val r = release.evaluate(clean.copy(adbEnabled = true, accessibilityNotAllowed = 2, onNonDefaultDisplay = true, deskMode = true))
        assertEquals(listOf(Stop.ENV_ACCESSIBILITY, Stop.ENV_ADB, Stop.ENV_EXTERNAL_DISPLAY), r.violations)
    }

    @Test fun dienstnamenNormaliserenEnAllowlist() {
        assertEquals("a.b/a.b.Svc", EnvironmentGuard.normalize("a.b/.Svc"))
        assertEquals(setOf("a.b/a.b.Svc", "c/c.D"), EnvironmentGuard.parseEnabledServices("a.b/.Svc: c/c.D :"))
        assertTrue(EnvironmentGuard.parseEnabledServices(null).isEmpty())
        val g = EnvironmentGuard(adbIsStop = true, accessibilityAllowlist = setOf("a.b/.Svc"))
        assertEquals(1, g.countNotAllowed(setOf("a.b/a.b.Svc", "c/c.D")))
        // standaard lege allowlist: elke dienst telt
        assertEquals(2, release.countNotAllowed(setOf("a.b/a.b.Svc", "c/c.D")))
    }

    @Test fun meldingenBevattenGeenDienstnamen() {
        val r = release.evaluate(clean.copy(accessibilityNotAllowed = 1, presentationDisplays = 1))
        val text = (r.violations.map { it.tekst + it.advies } + r.warnings.map { it.detail }).joinToString()
        assertFalse(text.contains("/"))
    }
}
