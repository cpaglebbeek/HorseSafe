package nl.icthorse.horsesafe

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * Bronbeleid deel 2 (HARDWARE_KEYS §7.2, §13.2, §13.9). Commentaar telt niet mee.
 *
 * - De PIN-code van deel 1 (`yubikey/`, `pin/`, `flow/`) importeert niets uit `net/` (en ook niet uit
 *   `pairing/`, `keystore/`, `biometric/`) en bevat geen java.net/okhttp.
 * - Netwerkcode (java.net, HttpsURLConnection, okhttp) staat alleen in `net/`.
 * - `BiometricPrompt` alleen in `biometric/`; altijd `BIOMETRIC_STRONG`, negatieve knop "Annuleren", elke
 *   `authenticate(` met een CryptoObject; geen DEVICE_CREDENTIAL (app-breed: SourcePolicyTest).
 * - `keystore/`: biometrische sleutels per gebruik (timeout 0), invalidated-by-enrollment, unlockedDeviceRequired,
 *   StrongBox eerst; nooit een validity-duur.
 * - network_security_config: alleen icthorsecloud.nl, geen cleartext, pins ISRG Root X1 + X2 tot 2028-12-31;
 *   de host is gelijk aan BuildConfig.API_BASE_URL, `net/HttpsTransport.ALLOWED_HOST` en de rpId.
 */
class PairingSourcePolicyTest {
    private val pkgRoot = listOf("src/main/java/nl/icthorse/horsesafe", "app/src/main/java/nl/icthorse/horsesafe")
        .map(::File).first { it.isDirectory }
    private val mainRoot = listOf("src/main", "app/src/main").map(::File).first { it.isDirectory }

    private fun code(t: String): String = t
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
        .replace(Regex("(?m)//[^\n]*"), " ")

    private fun ktFiles(dir: String): List<File> =
        File(pkgRoot, dir).walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java") }.toList()

    private fun rel(f: File) = f.relativeTo(pkgRoot).path.replace(File.separatorChar, '/')

    private val pinForbidden = Regex(
        "nl\\.icthorse\\.horsesafe\\.(net|pairing|keystore|biometric)\\b|java\\.net\\b|javax\\.net\\b|okhttp|HttpsURLConnection|HttpURLConnection",
    )
    private val netCode = Regex("java\\.net\\b|javax\\.net\\b|okhttp|HttpsURLConnection|HttpURLConnection|\\bSocket\\b")

    @Test fun pinCodeZonderNetwerk() {
        val files = listOf("yubikey", "pin", "flow").flatMap(::ktFiles)
        assertTrue("bronbestanden gevonden (${files.size})", files.size >= 30)
        val hits = files.filter { pinForbidden.containsMatchIn(code(it.readText())) }.map(::rel)
        assertEquals("PIN-code mag niets uit net/ (of pairing/keystore/biometric) gebruiken", emptyList<String>(), hits)
    }

    @Test fun netwerkcodeAlleenInNet() {
        val all = pkgRoot.walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java") }.toList()
        val hits = all.filter { netCode.containsMatchIn(code(it.readText())) }.map(::rel).filterNot { it.startsWith("net/") }
        assertEquals(emptyList<String>(), hits)
    }

    @Test fun biometrieAlleenViaStrongGate() {
        val all = pkgRoot.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        val users = all.filter { code(it.readText()).contains("BiometricPrompt") }.map(::rel).sorted()
        assertEquals(listOf("biometric/StrongGate.kt", "biometric/StrongGateFinger.kt"), users)
        val gate = code(File(pkgRoot, "biometric/StrongGate.kt").readText())
        assertTrue(gate.contains("setAllowedAuthenticators(BIOMETRIC_STRONG)"))
        assertTrue(gate.contains("canAuthenticate(BIOMETRIC_STRONG)"))
        assertTrue(gate.contains("setNegativeButtonText(NEGATIVE)"))
        assertTrue(gate.contains("const val NEGATIVE = \"Annuleren\""))
        assertTrue(gate.contains("AUTHENTICATION_RESULT_TYPE_BIOMETRIC"))
        // Geen andere authenticator-klassen.
        listOf("BIOMETRIC_WEAK", "setDeviceCredentialAllowed", "Authenticators.DEVICE").forEach {
            assertTrue("StrongGate bevat $it", !gate.contains(it))
        }
        // Elke authenticate-aanroep heeft twee argumenten (PromptInfo + CryptoObject).
        val calls = Regex("\\.authenticate\\(([^()]*)\\)").findAll(gate).map { it.groupValues[1] }.toList()
        assertTrue("authenticate-aanroep gevonden", calls.isNotEmpty())
        calls.forEach { assertEquals("authenticate($it) zonder CryptoObject", 2, it.split(",").size) }
    }

    @Test fun keystoreEigenschappen() {
        val ks = code(File(pkgRoot, "keystore/AndroidPhoneKeys.kt").readText())
        assertEquals("invalidated-by-enrollment voor K_biosig en K_wrap", 2, Regex("setInvalidatedByBiometricEnrollment\\(true\\)").findAll(ks).count())
        assertEquals("per gebruik, alleen biometrie STRONG", 2, Regex("setUserAuthenticationParameters\\(0, KeyProperties\\.AUTH_BIOMETRIC_STRONG\\)").findAll(ks).count())
        assertEquals("unlockedDeviceRequired voor K_dev en K_wrap", 2, Regex("setUnlockedDeviceRequired\\(true\\)").findAll(ks).count())
        assertTrue(ks.contains("setAttestationChallenge(challenge)"))
        assertTrue(ks.contains("setIsStrongBoxBacked(strongBox)"))
        // StrongBox eerst, terugval op de TEE bij StrongBoxUnavailableException/ProviderException (StrongBoxFallback)
        assertEquals("K_dev/K_biosig en K_wrap via StrongBoxFallback", 2, Regex("StrongBoxFallback\\.generate \\{ strongBox ->").findAll(ks).count())
        val fb = code(File(pkgRoot, "keystore/StrongBoxFallback.kt").readText())
        assertTrue(fb.contains("gen(true)") && fb.contains("catch (e: ProviderException)") && fb.contains("gen(false)"))
        listOf("setUserAuthenticationValidityDurationSeconds", "AUTH_DEVICE_CREDENTIAL", "setUserAuthenticationValidWhileOnBody", "setUnlockedDeviceRequired(false)")
            .forEach { assertTrue("keystore bevat $it", !ks.contains(it)) }
    }

    @Test fun netwerkbeleid() {
        val f = File(mainRoot, "res/xml/network_security_config.xml")
        val doc = DocumentBuilderFactory.newInstance().apply {
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        }.newDocumentBuilder().parse(f)
        fun els(tag: String): List<Element> = doc.getElementsByTagName(tag).let { nl -> (0 until nl.length).map { nl.item(it) as Element } }
        val base = els("base-config").single()
        assertEquals("false", base.getAttribute("cleartextTrafficPermitted"))
        val baseAnchors = base.getElementsByTagName("certificates")
        assertEquals("base-config vertrouwt niets", 0, baseAnchors.length)
        val dc = els("domain-config").single()
        assertEquals("false", dc.getAttribute("cleartextTrafficPermitted"))
        val domains = els("domain")
        assertEquals(1, domains.size)
        assertEquals(EXPECTED_HOST, domains.single().textContent.trim())
        assertEquals("false", domains.single().getAttribute("includeSubdomains"))
        val pinSet = els("pin-set").single()
        assertEquals("2028-12-31", pinSet.getAttribute("expiration"))
        val pins = els("pin").map { it.getAttribute("digest") to it.textContent.trim() }.toSet()
        assertEquals(setOf(ISRG_X1, ISRG_X2, ISRG_YE, ISRG_YR).map { "SHA-256" to it }.toSet(), pins)
        assertEquals(0, els("debug-overrides").size)
        assertEquals(listOf("system"), els("certificates").map { it.getAttribute("src") })
    }

    @Test fun hostOveralGelijk() {
        val base = BuildConfig.API_BASE_URL
        assertEquals("https://$EXPECTED_HOST/HorseSafe/api", base)
        assertEquals(EXPECTED_HOST, nl.icthorse.horsesafe.net.HttpsTransport.ALLOWED_HOST)
        assertEquals(EXPECTED_HOST, nl.icthorse.horsesafe.yubikey.api.ConfigOps.MIN_PIN_RP_ID)
    }

    @Test fun regelsVangenVerbodenCode() {
        listOf(
            "import nl.icthorse.horsesafe.net.DeviceApi",
            "val x = nl.icthorse.horsesafe.net.HttpsTransport(u)",
            "import java.net.URL",
            "import javax.net.ssl.HttpsURLConnection",
            "okhttp3.OkHttpClient()",
            "import nl.icthorse.horsesafe.pairing.PairingFlow",
        ).forEach { assertTrue("zelftest vangt niet: $it", pinForbidden.containsMatchIn(code(it))) }
        assertTrue(!pinForbidden.containsMatchIn(code("// import nl.icthorse.horsesafe.net.DeviceApi\nval network = 1")))
    }

    private companion object {
        const val EXPECTED_HOST = "icthorsecloud.nl"

        /** SPKI-SHA-256 van ISRG Root X1/X2/YE/YR, berekend op 2026-10-14 uit letsencrypt.org/certs/. */
        const val ISRG_X1 = "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="
        const val ISRG_X2 = "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI="
        const val ISRG_YE = "sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w="
        const val ISRG_YR = "fk6IOKit1ild5647BH06ujSIq5XbCgqlbYl6ANhhi88="
    }
}
