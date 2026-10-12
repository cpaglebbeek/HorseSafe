package nl.icthorse.horsesafe.ui

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Bronbeleid voor `ui/`, `secure/` en `app/` (A-6, A-10, A-11, A-13, A-16, A-18): geen tekstvelden,
 * klembord of selectie, geen opslag van geheimen in saveable state, geen logging, geen netwerk, geen
 * DEVICE_CREDENTIAL/biometrie, geen gevaarlijke sleutelbewerkingen en de domeinnaam van de server niet
 * (die staat alleen in `yubikey/api/ConfigOps.kt`). Commentaar telt niet mee.
 */
class UiSourcePolicyTest {
    private val root = listOf("src/main/java/nl/icthorse/horsesafe", "app/src/main/java/nl/icthorse/horsesafe")
        .map(::File).first { it.isDirectory }

    private val dirs = listOf("ui", "secure", "app").map { File(root, it) }

    private fun code(f: File): String =
        f.readText()
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
            .replace(Regex("//[^\n]*"), " ")

    private val forbidden = listOf(
        Regex("\\bTextField\\b|BasicTextField|OutlinedTextField|EditText|TextInputService|LocalSoftwareKeyboardController"),
        Regex("SelectionContainer|ClipboardManager|LocalClipboardManager|setPrimaryClip"),
        Regex("rememberSaveable|SavedStateHandle|onSaveInstanceState|putCharArray|putString\\("),
        Regex("android\\.util\\.Log|\\bLog\\.[dewiv]\\(|println|printStackTrace|System\\.(out|err)"),
        Regex("icthorsecloud\\.nl"),
        Regex("DEVICE_CREDENTIAL|BiometricPrompt|USE_BIOMETRIC"),
        Regex("java\\.net|okhttp|\\bSocket\\b|HttpURLConnection"),
        Regex("kotlin\\.random|java\\.util\\.Random\\b|Math\\.random"),
        Regex("String\\s*\\(\\s*(chars|pin|a|arr)\\b|concatToString|String\\.valueOf\\(\\s*(chars|pin|a|arr)"),
        Regex("getCachedInfo|deviceReset\\(|deleteCredential\\(|enableEnterpriseAttestation\\(|updateDeviceConfig\\(|setMode\\("),
        Regex("Crashlytics|ACRA|FirebaseApp"),
    )

    @Test fun geenVerbodenApis() {
        val files = dirs.flatMap { d -> d.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }
        assertTrue("ui/secure/app bevatten bronbestanden", files.size >= 15)
        val hits = files.flatMap { f -> val c = code(f); forbidden.filter { it.containsMatchIn(c) }.map { "${f.name}: ${it.pattern}" } }
        assertTrue("verboden in ui/secure/app: $hits", hits.isEmpty())
    }

    @Test fun toetsenblokEnPinKaartenBuitenToegankelijkheidsboom() {
        val keypad = code(File(root, "ui/components/PinKeypad.kt"))
        val reveal = code(File(root, "ui/components/GroupReveal.kt"))
        assertTrue(keypad.contains("clearAndSetSemantics"))
        assertTrue(reveal.contains("clearAndSetSemantics"))
        // glyphs uit een CharArray, niet als String
        assertTrue(reveal.contains("drawText(chars, start, count"))
    }

    @Test fun vensterRegelsAanwezig() {
        val sw = code(File(root, "secure/SecureWindow.kt"))
        listOf("FLAG_SECURE", "setRecentsScreenshotEnabled(false)", "setHideOverlayWindows(true)", "filterTouchesWhenObscured = true",
            "ACCESSIBILITY_DATA_SENSITIVE_YES", "IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS", "IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS")
            .forEach { assertTrue("SecureWindow mist $it", sw.contains(it)) }
        val act = code(File(root, "app/MainActivity.kt"))
        val before = act.indexOf("SecureWindow.beforeContent")
        val content = act.indexOf("setContent {")
        assertTrue("vensterregels vóór setContent", before in 0 until content)
        assertTrue(act.contains("CrashGuard.install"))
        assertTrue(act.contains("ProcessEnd.end"))
    }
}
