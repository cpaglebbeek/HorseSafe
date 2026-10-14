package nl.icthorse.horsesafe

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Bronbeleid voor `yubikey/` en `flow/` (A-16, A-18, kritiek 18): juist hier zouden gevaarlijke
 * yubikit-aanroepen of netwerk- en bestandscode terechtkomen. Commentaar telt niet mee.
 *
 * - geen netwerk (java.net, okhttp, Socket, HttpURLConnection) en geen bestanden (java.io.File,
 *   FileInputStream/FileOutputStream, openFileInput/openFileOutput);
 * - geen reset, deleteCredential, enableEnterpriseAttestation, updateDeviceConfig, setMode, deviceReset
 *   en geen getCachedInfo (kritiek 18: in eigen code volledig verboden);
 * - geen logging;
 * - `"icthorsecloud.nl"` in de hele main-tree alleen in `yubikey/api/ConfigOps.kt`, en sinds deel 2 in
 *   `net/HttpTransport.kt` (toegestane host) en `res/xml/network_security_config.xml` (pins); strings.xml en
 *   de UI-teksten noemen het domein niet. Gelijk aan `webauthn_rp_id` in `backend/config.py`.
 */
class YubikeyFlowSourcePolicyTest {
    private val pkgRoot = listOf("src/main/java/nl/icthorse/horsesafe", "app/src/main/java/nl/icthorse/horsesafe")
        .map(::File).first { it.isDirectory }
    private val mainRoot = listOf("src/main", "app/src/main").map(::File).first { it.isDirectory }

    private fun code(t: String): String = t
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
        .replace(Regex("(?m)//[^\n]*"), " ")

    private fun xmlCode(t: String) = t.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), " ")

    private val forbidden = listOf(
        "netwerk" to Regex("java\\.net\\b|okhttp|\\bSocket\\b|HttpURLConnection|URLConnection"),
        "bestanden" to Regex("java\\.io\\.File\\b|\\bFileInputStream\\b|\\bFileOutputStream\\b|openFileInput|openFileOutput|\\bRandomAccessFile\\b"),
        "A-18" to Regex("deviceReset\\s*\\(|deleteCredential\\s*\\(|enableEnterpriseAttestation\\s*\\(|updateDeviceConfig\\s*\\(|setMode\\s*\\("),
        "reset" to Regex("\\bctap\\w*\\.reset\\s*\\(|Ctap2Session[^\\n]*\\.reset\\s*\\(|session\\.reset\\s*\\("),
        "getCachedInfo" to Regex("getCachedInfo"),
        "logging" to Regex("android\\.util\\.Log\\b|\\bLog\\.(v|d|i|w|e|wtf|println)\\s*\\(|\\bprintln\\s*\\(|printStackTrace|System\\.(out|err)\\b"),
    )

    private fun hits(name: String, c: String): List<String> =
        forbidden.filter { (_, re) -> re.containsMatchIn(c) }.map { (label, _) -> "$name: $label" }

    @Test fun yubikeyEnFlowZonderVerbodenCode() {
        val files = listOf("yubikey", "flow").map { File(pkgRoot, it) }
            .flatMap { d -> d.walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java") }.toList() }
        assertTrue("yubikey/ en flow/ bevatten bronbestanden (${files.size})", files.size >= 25)
        val h = files.flatMap { f -> hits(f.relativeTo(pkgRoot).path, code(f.readText())) }
            .filterNot { it == RESET_ALLOWED + ": reset" }
        assertTrue("bronbeleid yubikey/flow geschonden:\n" + h.joinToString("\n"), h.isEmpty())
    }

    /** 0.3.1: de reset staat in precies één bestand, en alleen ResetFlow gebruikt [ResetOps]. */
    @Test fun resetAlleenInYubikitResetOps() {
        val all = pkgRoot.walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java") }.toList()
        val resetRe = forbidden.first { it.first == "reset" }.second
        val withReset = all.filter { resetRe.containsMatchIn(code(it.readText())) }.map { it.relativeTo(pkgRoot).path.replace(File.separatorChar, '/') }
        assertEquals(listOf(RESET_ALLOWED), withReset)
        val users = all.filter { Regex("\\.wipeFido\\s*\\(").containsMatchIn(code(it.readText())) }
            .map { it.relativeTo(pkgRoot).path.replace(File.separatorChar, '/') }
        assertEquals(listOf("flow/ResetFlow.kt"), users)
    }

    private companion object {
        const val RESET_ALLOWED = "yubikey/YubikitResetOps.kt"
    }

    @Test fun domeinAlleenInConfigOps() {
        val all = mainRoot.walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java", "xml") }.toList()
        assertTrue(all.size >= 60)
        val where = all.filter { f ->
            val t = f.readText()
            (if (f.extension == "xml") xmlCode(t) else code(t)).contains("icthorsecloud.nl")
        }.map { it.relativeTo(mainRoot).path.replace(File.separatorChar, '/') }
        assertEquals(
            listOf(
                "java/nl/icthorse/horsesafe/net/HttpTransport.kt",
                "java/nl/icthorse/horsesafe/yubikey/api/ConfigOps.kt",
                "res/xml/network_security_config.xml",
            ),
            where.sorted(),
        )
    }

    @Test fun rpIdGelijkAanBackend() {
        val cfg = listOf("../backend/config.py", "../../backend/config.py").map(::File).firstOrNull { it.isFile }
            ?: error("backend/config.py niet gevonden")
        val m = Regex("webauthn_rp_id\\s*:\\s*str\\s*=\\s*\"([^\"]+)\"").find(cfg.readText()) ?: error("webauthn_rp_id niet gevonden")
        assertEquals(m.groupValues[1], nl.icthorse.horsesafe.yubikey.api.ConfigOps.MIN_PIN_RP_ID)
    }

    /** Zelftest: de regels vangen de verboden code echt, en commentaar telt niet. */
    @Test fun regelsVangenVerbodenCode() {
        val bad = listOf(
            "import java.net.URL",
            "val c = okhttp3.OkHttpClient()",
            "val f = java.io.File(\"x\")",
            "FileOutputStream(x)",
            "mgmt.deviceReset()",
            "cm.deleteCredential(id)",
            "cfg.enableEnterpriseAttestation(t)",
            "mgmt.updateDeviceConfig(c, true, null, null)",
            "mgmt.setMode(m)",
            "ctap.reset(null)",
            "session.getCachedInfo()",
            "Log.d(\"x\", \"y\")",
        )
        bad.forEach { line -> assertTrue("zelftest vangt niet: $line", hits("t", code(line)).isNotEmpty()) }
        val ok = code("// deviceReset() \n/* getCachedInfo */\nval md = MessageDigest.getInstance(\"SHA-256\"); md.reset(); mac.reset()")
        assertTrue("valse treffer: ${hits("t", ok)}", hits("t", ok).isEmpty())
    }
}
