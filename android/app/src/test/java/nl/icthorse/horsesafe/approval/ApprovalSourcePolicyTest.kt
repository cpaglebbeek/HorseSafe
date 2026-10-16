package nl.icthorse.horsesafe.approval

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Bronbeleid Montgomery (HARDWARE_KEYS §14.9, E1/E2). Commentaar telt niet mee.
 *
 * - Nieuwe code (`approval/`, `crypto/TrustV1.kt`, `ui/ApprovalViewModel.kt`, `ui/screens/ApprovalScreen.kt`):
 *   geen toestel-PIN-terugval, geen eigen BiometricPrompt (alleen via `biometric/StrongGate` met CryptoObject),
 *   geen netwerkcode buiten `net/`, geen logging.
 * - De vinger voor goedkeuren loopt via `Finger.cipher` (CryptoObject met K_wrap) met stap APPROVE.
 * - In `approve` komt de handtekeningcontrole vóór de vinger.
 * - De PIN-code (`yubikey/`, `pin/`, `flow/`) gebruikt niets uit `approval/`.
 */
class ApprovalSourcePolicyTest {
    private val pkgRoot = listOf("src/main/java/nl/icthorse/horsesafe", "app/src/main/java/nl/icthorse/horsesafe")
        .map(::File).first { it.isDirectory }

    private fun code(t: String): String = t
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
        .replace(Regex("(?m)//[^\n]*"), " ")

    private fun read(rel: String) = code(File(pkgRoot, rel).readText())

    private val newFiles: List<String> by lazy {
        File(pkgRoot, "approval").walkTopDown().filter { it.isFile && it.extension == "kt" }
            .map { it.relativeTo(pkgRoot).path.replace(File.separatorChar, '/') }.toList() +
            listOf("crypto/TrustV1.kt", "ui/ApprovalViewModel.kt", "ui/screens/ApprovalScreen.kt")
    }

    /** Woorden in delen, zodat dit testbestand zelf niet als overtreding telt. */
    private val forbidden = listOf(
        "DEVICE_" + "CREDENTIAL", "BIOMETRIC_" + "WEAK", "setDeviceCredential" + "Allowed", "KeyguardManager",
        "Biometric" + "Prompt", "java.net", "javax.net", "HttpsURL" + "Connection", "okhttp", "android.util.Log", "println(",
    )

    @Test fun geenPinTerugvalGeenEigenPromptGeenNetwerk() {
        assertTrue("approval/ gevonden", newFiles.any { it.startsWith("approval/") })
        val hits = newFiles.flatMap { f -> val c = read(f); forbidden.filter { c.contains(it) }.map { "$f: $it" } }
        assertEquals(emptyList<String>(), hits)
    }

    @Test fun vingerAlleenViaCryptoObjectMetK_wrap() {
        val flow = read("approval/ApprovalFlow.kt")
        val calls = Regex("finger\\.(\\w+)\\(").findAll(flow).map { it.groupValues[1] }.toList()
        assertEquals("precies één vinger, via Cipher (K_wrap)", listOf("cipher"), calls)
        assertTrue(flow.contains("keys.unwrapCipher(rec.slot, rec.wrappedIv) }, FingerStep.APPROVE)"))
    }

    @Test fun handtekeningVoorDeVinger() {
        val flow = read("approval/ApprovalFlow.kt")
        val approve = flow.substring(flow.indexOf("suspend fun approve("))
        val sig = approve.indexOf("signatureValid(req)")
        val finger = approve.indexOf("finger.cipher(")
        assertTrue("sig_req-controle vóór de vinger", sig in 0 until finger)
        val load = flow.substring(flow.indexOf("fun load("), flow.indexOf("fun signatureValid("))
        assertTrue("load vraagt geen vinger", !load.contains("finger."))
    }

    @Test fun geheimenWordenGewist() {
        val flow = read("approval/ApprovalFlow.kt")
        assertTrue(flow.contains("sk?.fill(0)") && flow.contains("ck?.wipe()"))
        val trust = read("crypto/TrustV1.kt")
        assertTrue("k_bind gewist", Regex("k\\.fill\\(0\\)").findAll(trust).count() >= 2)
        assertTrue("pt_ck gewist", trust.contains("pt.fill(0)"))
    }

    @Test fun pinCodeGebruiktGeenApproval() {
        val files = listOf("yubikey", "pin", "flow").flatMap { d -> File(pkgRoot, d).walkTopDown().filter { it.isFile && it.extension == "kt" }.toList() }
        assertTrue(files.size >= 30)
        val hits = files.filter { code(it.readText()).contains("nl.icthorse.horsesafe.approval") }.map { it.name }
        assertEquals(emptyList<String>(), hits)
    }
}
