package nl.icthorse.horsesafe

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * Leest de MERGED release-manifest (dus inclusief alles wat afhankelijkheden toevoegen) en controleert
 * de harde regels uit A-14/A-15: geen INTERNET, geen biometrie, geen backup, niet debuggable, precies één
 * exported component met alleen de launcher-intent-filter, geen USB/NFC-intent-filters.
 *
 * Het pad komt uit de Gradle-koppeling in app/build.gradle.kts (systeemeigenschap horsesafe.releaseManifest).
 * Ontbreekt die, dan faalt de test (fail-closed) in plaats van stil over te slaan.
 */
class ReleaseManifestTest {
    private val ns = "http://schemas.android.com/apk/res/android"

    private val manifestFile: File by lazy {
        val p = System.getProperty("horsesafe.releaseManifest")
            ?: error("horsesafe.releaseManifest niet gezet: draai via Gradle")
        File(p).also { assertTrue("merged release-manifest bestaat niet: $p", it.isFile) }
    }

    private val doc by lazy {
        DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        }.newDocumentBuilder().parse(manifestFile)
    }

    private fun elements(tag: String): List<Element> {
        val nl = doc.getElementsByTagName(tag)
        return (0 until nl.length).map { nl.item(it) as Element }
    }

    private fun Element.a(name: String): String? = getAttributeNS(ns, name).takeIf { hasAttributeNS(ns, name) }

    /** Manifesttekst zonder XML-commentaar (het bron-commentaar wordt in de merged manifest overgenomen). */
    private val manifestCode: String by lazy {
        manifestFile.readText().replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), " ")
    }

    private val application: Element by lazy { elements("application").single() }

    @Test fun pakketIsReleasePakket() {
        assertEquals("nl.icthorse.horsesafe", doc.documentElement.getAttribute("package"))
    }

    @Test fun alleenToegestanePermissies() {
        val perms = elements("uses-permission").mapNotNull { it.a("name") }.toSet() +
            elements("uses-permission-sdk-23").mapNotNull { it.a("name") }
        val forbidden = setOf(
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        )
        assertTrue("verboden permissies in release: ${perms intersect forbidden}", (perms intersect forbidden).isEmpty())
        val allowed = setOf(
            "android.permission.NFC",
            "android.permission.HIDE_OVERLAY_WINDOWS",
            "android.permission.DETECT_SCREEN_CAPTURE",
            "android.permission.DETECT_SCREEN_RECORDING",
            "nl.icthorse.horsesafe.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
        )
        assertEquals("permissieset release", allowed, perms)
        assertFalse(manifestCode.contains("DEVICE_CREDENTIAL"))
    }

    @Test fun geenBackupNietDebuggable() {
        assertEquals("false", application.a("allowBackup"))
        val dbg = application.a("debuggable")
        assertTrue("release is debuggable", dbg == null || dbg == "false")
        val testOnly = application.a("testOnly")
        assertTrue("release is testOnly", testOnly == null || testOnly == "false")
        assertEquals("false", application.a("usesCleartextTraffic"))
    }

    @Test fun eenExportedComponentMetAlleenLauncherFilter() {
        val components = listOf("activity", "activity-alias", "service", "receiver", "provider").flatMap(::elements)
        val exported = components.filter { it.a("exported") == "true" }.map { it.a("name") }
        assertEquals(listOf("nl.icthorse.horsesafe.app.MainActivity"), exported)

        val filters = elements("intent-filter")
        assertEquals("aantal intent-filters", 1, filters.size)
        val f = filters.single()
        assertEquals("nl.icthorse.horsesafe.app.MainActivity", (f.parentNode as Element).a("name"))
        val actions = (0 until f.getElementsByTagName("action").length)
            .map { (f.getElementsByTagName("action").item(it) as Element).a("name") }
        val cats = (0 until f.getElementsByTagName("category").length)
            .map { (f.getElementsByTagName("category").item(it) as Element).a("name") }
        assertEquals(listOf("android.intent.action.MAIN"), actions)
        assertEquals(listOf("android.intent.category.LAUNCHER"), cats)
        assertEquals("geen data-elementen in intent-filter", 0, f.getElementsByTagName("data").length)

        assertEquals("geen providers (A-15)", emptyList<String>(), elements("provider").map { it.a("name") })
        assertEquals("geen services (A-15)", emptyList<String>(), elements("service").map { it.a("name") })

        val text = manifestCode
        listOf("InitializationProvider", "USB_DEVICE_ATTACHED", "NDEF_DISCOVERED", "TECH_DISCOVERED", "TAG_DISCOVERED", "device_filter",
            "OtpActivity", "YubiKeyPromptActivity", "ProfileInstallReceiver")
            .forEach { assertFalse("release-manifest bevat $it", text.contains(it)) }
    }
}
