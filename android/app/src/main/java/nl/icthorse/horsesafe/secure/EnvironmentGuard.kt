package nl.icthorse.horsesafe.secure

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.UiModeManager
import android.content.Context
import android.content.res.Configuration
import android.hardware.display.DisplayManager
import android.provider.Settings
import android.view.Display
import android.view.accessibility.AccessibilityManager
import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Verdict

/**
 * Momentopname van de omgeving (F0, A-4, A-8, kritiek 19). Bevat geen namen van diensten of apps,
 * alleen aantallen en vlaggen, zodat hij veilig in state en tests mag.
 */
data class EnvSnapshot(
    /** `Settings.Global.ADB_ENABLED == 1`. */
    val adbEnabled: Boolean,
    /** Aantal actieve toegankelijkheidsdiensten die NIET op de allowlist staan. */
    val accessibilityNotAllowed: Int,
    val inMultiWindow: Boolean,
    val inPictureInPicture: Boolean,
    /** `display.displayId != DEFAULT_DISPLAY`. */
    val onNonDefaultDisplay: Boolean,
    /** `UiModeManager.currentModeType == UI_MODE_TYPE_DESK`. */
    val deskMode: Boolean,
    /** Samsung DeX via reflectie; null = niet vast te stellen (geen Samsung of API weg). */
    val samsungDex: Boolean?,
    /** Aantal extra presentatieschermen (Cast, HDMI, Smart View). FLAG_SECURE maakt die zwart: melding. */
    val presentationDisplays: Int,
    /** Schermopname zichtbaar (API 35, [ScreenWatch]). */
    val screenRecording: Boolean,
    /**
     * `adb_wifi_enabled == 1` (Draadloze foutopsporing, Android 11+; staat los van ADB_ENABLED).
     * Verborgen sleutel: niet leesbaar = false, want [developerOptions] dekt dit pad al fail-closed af.
     */
    val adbWifiEnabled: Boolean = false,
    /**
     * `Settings.Global.DEVELOPMENT_SETTINGS_ENABLED == 1` (publiek). Draadloze foutopsporing, "Tikken
     * weergeven" en "Aanwijzerlocatie" (systeemoverlays buiten FLAG_SECURE) kunnen alleen aan met
     * ontwikkelaarsopties aan. Niet leesbaar = true (fail-closed).
     */
    val developerOptions: Boolean = false,
)

/** Uitkomst: [violations] blokkeren de schermen met een geheim (M4, M6, M8); [warnings] zijn meldingen. */
data class EnvReport(val violations: List<Stop>, val warnings: List<CheckResult>) {
    val blocksSecrets: Boolean get() = violations.isNotEmpty()

    companion object {
        val CLEAN = EnvReport(emptyList(), emptyList())
    }
}

/**
 * Beoordeelt de omgeving vóór de schermen met een geheim. Een overtreding blokkeert alleen de schermen
 * met een geheim (M4, M6, M8); de overige schermen blijven werken (F0.3).
 *
 * - ADB aan (USB of draadloos) of ontwikkelaarsopties aan: STOP als [adbIsStop] (release-build), anders
 *   alleen een oranje waarschuwing (debug-build, ontwikkelen op de emulator). Met ADB kan `getevent` de
 *   tikposities op het vaste toetsenblok meelezen; "Tikken weergeven" tekent ze in een systeemoverlay.
 * - Een toegankelijkheidsdienst die niet op de allowlist staat (standaard leeg, open vraag 10): STOP.
 * - Multi-window, beeld-in-beeld: STOP.
 * - Ander display dan DEFAULT_DISPLAY, desk-modus of Samsung DeX: STOP.
 * - Schermopname: STOP.
 * - Extra presentatiescherm (spiegelen/casten): oranje melding (FLAG_SECURE maakt het zwart).
 */
class EnvironmentGuard(
    private val adbIsStop: Boolean,
    /** Component-namen (`pakket/klasse`) die wel mogen. Standaard leeg. */
    accessibilityAllowlist: Set<String> = emptySet(),
) {
    private val allow: Set<String> = accessibilityAllowlist.map(::normalize).toSet()

    fun evaluate(s: EnvSnapshot): EnvReport {
        val v = mutableListOf<Stop>()
        val w = mutableListOf<CheckResult>()
        if (s.accessibilityNotAllowed > 0) v += Stop.ENV_ACCESSIBILITY
        if (s.adbEnabled || s.adbWifiEnabled || s.developerOptions) {
            if (adbIsStop) {
                v += Stop.ENV_ADB
            } else {
                w += CheckResult(ID_ADB, Verdict.ORANGE, "Ontwikkelaarsopties of foutopsporing (USB of draadloos) staan aan. In de release-build blokkeert dit de PIN-schermen.")
            }
        }
        if (s.inMultiWindow || s.inPictureInPicture) v += Stop.ENV_MULTI_WINDOW
        if (s.onNonDefaultDisplay || s.deskMode || s.samsungDex == true) v += Stop.ENV_EXTERNAL_DISPLAY
        if (s.screenRecording) v += Stop.ENV_SCREEN_RECORDING
        if (s.presentationDisplays > 0) {
            w += CheckResult(ID_DISPLAY, Verdict.ORANGE, "Er is een extra scherm verbonden (casten of spiegelen). Dat scherm blijft zwart; koppel het liever los.")
        }
        return EnvReport(v.distinct(), w)
    }

    /** Leest de omgeving op het toestel. Alle systeemaanroepen en reflectie fail-safe. */
    fun snapshot(activity: Activity, screenRecording: Boolean): EnvSnapshot {
        val ctx: Context = activity
        return EnvSnapshot(
            adbEnabled = readAdb(ctx),
            adbWifiEnabled = readAdbWifi(ctx),
            developerOptions = readDeveloperOptions(ctx),
            accessibilityNotAllowed = countAccessibility(ctx),
            inMultiWindow = activity.isInMultiWindowMode,
            inPictureInPicture = activity.isInPictureInPictureMode,
            onNonDefaultDisplay = (activity.display?.displayId ?: Display.DEFAULT_DISPLAY) != Display.DEFAULT_DISPLAY,
            deskMode = readDeskMode(ctx),
            samsungDex = samsungDex(ctx.resources.configuration),
            presentationDisplays = presentationDisplays(ctx),
            screenRecording = screenRecording,
        )
    }

    fun check(activity: Activity, screenRecording: Boolean): EnvReport = evaluate(snapshot(activity, screenRecording))

    private fun readAdb(ctx: Context): Boolean = try {
        Settings.Global.getInt(ctx.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    } catch (e: RuntimeException) {
        true // fail-closed
    }

    /** Verborgen sleutel `adb_wifi_enabled`; een SecurityException (niet leesbaar) telt als false, zie [EnvSnapshot]. */
    private fun readAdbWifi(ctx: Context): Boolean = try {
        Settings.Global.getInt(ctx.contentResolver, ADB_WIFI_ENABLED, 0) == 1
    } catch (e: RuntimeException) {
        false
    }

    private fun readDeveloperOptions(ctx: Context): Boolean = try {
        Settings.Global.getInt(ctx.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
    } catch (e: RuntimeException) {
        true // fail-closed
    }

    private fun readDeskMode(ctx: Context): Boolean = try {
        ctx.getSystemService(UiModeManager::class.java)?.currentModeType == Configuration.UI_MODE_TYPE_DESK
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Telt actieve diensten buiten de allowlist. Twee bronnen (de AccessibilityManager-lijst kan door
     * pakketzichtbaarheid onvolledig zijn): de manager en `Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES`.
     * De namen worden alleen geteld, nooit getoond of gelogd.
     */
    private fun countAccessibility(ctx: Context): Int {
        val ids = mutableSetOf<String>()
        try {
            val am = ctx.getSystemService(AccessibilityManager::class.java)
            am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)?.forEach { info ->
                info.id?.let { ids += normalize(it) }
            }
        } catch (e: RuntimeException) {
            return 1 // fail-closed
        }
        try {
            ids += parseEnabledServices(Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES))
        } catch (e: RuntimeException) {
            // instelling niet leesbaar: alleen de managerlijst telt
        }
        return countNotAllowed(ids)
    }

    internal fun countNotAllowed(ids: Set<String>): Int = ids.count { normalize(it) !in allow }

    private fun presentationDisplays(ctx: Context): Int = try {
        ctx.getSystemService(DisplayManager::class.java)
            ?.getDisplays(DisplayManager.DISPLAY_CATEGORY_PRESENTATION)
            ?.count { it.displayId != Display.DEFAULT_DISPLAY } ?: 0
    } catch (e: RuntimeException) {
        0
    }

    companion object {
        const val ID_ADB = "omgeving_adb"
        const val ID_DISPLAY = "omgeving_extra_scherm"

        /** `Settings.Global.ADB_WIFI_ENABLED` is @hide; de waarde is sinds API 30 deze sleutel. */
        internal const val ADB_WIFI_ENABLED = "adb_wifi_enabled"

        /** `pakket/.Klasse` en `pakket/pakket.Klasse` gelijk maken. */
        internal fun normalize(id: String): String {
            val slash = id.indexOf('/')
            if (slash <= 0) return id.trim()
            val pkg = id.substring(0, slash).trim()
            val cls = id.substring(slash + 1).trim()
            return "$pkg/" + if (cls.startsWith(".")) pkg + cls else cls
        }

        /** `a/b:c/d` → {a/b, c/d}. */
        internal fun parseEnabledServices(raw: String?): Set<String> =
            raw.orEmpty().split(':').map { it.trim() }.filter { it.isNotEmpty() }.map(::normalize).toSet()

        /**
         * Samsung DeX: `Configuration.semDesktopModeEnabled == Configuration.SEM_DESKTOP_MODE_ENABLED`.
         * Alleen als extra (kritiek 19), met try/catch; null = niet vast te stellen.
         */
        internal fun samsungDex(config: Configuration): Boolean? = try {
            val c = config.javaClass
            val enabledConst = c.getField("SEM_DESKTOP_MODE_ENABLED").getInt(null)
            val current = c.getField("semDesktopModeEnabled").getInt(config)
            current == enabledConst
        } catch (e: ReflectiveOperationException) {
            null
        } catch (e: RuntimeException) {
            null
        }
    }
}
