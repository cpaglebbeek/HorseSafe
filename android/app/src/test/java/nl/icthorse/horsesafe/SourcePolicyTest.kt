package nl.icthorse.horsesafe

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * App-breed bronbeleid over ALLE bestanden onder app/src/main (Kotlin, Java, XML): aanvulling op de
 * package-tests (pin/, attest/, ui/). Commentaar telt niet mee.
 *
 * - DEVICE_CREDENTIAL komt nergens voor (A-16, nooit PIN-terugval);
 * - android.permission.INTERNET / Manifest.permission.INTERNET komt nergens voor, behalve in precies één
 *   `<uses-permission>`-regel in het bronmanifest (deel 2, HARDWARE_KEYS §13.9);
 * - geen android.util.Log, println, printStackTrace of System.out/err in productiecode, en in het
 *   bijzonder nooit een logregel waarin pin/token voorkomt (A-13).
 */
class SourcePolicyTest {
    private val main = listOf("src/main", "app/src/main").map(::File).first { it.isDirectory }

    private fun kotlinCode(t: String) = t
        .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
        .replace(Regex("(?m)//[^\n]*"), " ")

    private fun xmlCode(t: String) = t.replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), " ")

    private fun sources(): List<Pair<File, String>> =
        main.absoluteFile.walkTopDown().filter { it.isFile && it.extension in setOf("kt", "java", "xml") }.map { f ->
            val t = f.readText()
            f to if (f.extension == "xml") xmlCode(t) else kotlinCode(t)
        }.toList()

    private val deviceCredential = Regex("DEVICE_CREDENTIAL")
    private val internet = Regex("android\\.permission\\.INTERNET|permission\\.INTERNET\\b")
    private val anyLog = Regex("android\\.util\\.Log\\b|\\bLog\\.(v|d|i|w|e|wtf|println)\\s*\\(|\\bprintln\\s*\\(|printStackTrace|System\\.(out|err)\\b|Timber\\.")
    private val logWithSecret = Regex("(?i)\\b(Log\\.\\w+|println|Timber\\.\\w+)\\s*\\([^)]*(pin|token)")

    private fun internetAllowed(f: File, line: String) =
        f.name == "AndroidManifest.xml" && line.trim() == INTERNET_LINE

    private fun hits(src: List<Pair<File, String>>): List<String> = src.flatMap { (f, code) ->
        val rel = f.relativeToOrSelf(main.absoluteFile).path
        code.lines().withIndex().flatMap { (i, line) ->
            buildList {
                if (deviceCredential.containsMatchIn(line)) add("$rel:${i + 1} DEVICE_CREDENTIAL")
                if (internet.containsMatchIn(line) && !internetAllowed(f, line)) add("$rel:${i + 1} INTERNET")
                if (logWithSecret.containsMatchIn(line)) add("$rel:${i + 1} log met pin/token")
                else if (f.extension != "xml" && anyLog.containsMatchIn(line)) add("$rel:${i + 1} logging")
            }
        }
    }

    @Test fun geenVerbodenConstructiesInProductiecode() {
        val src = sources()
        assertTrue("te weinig bronbestanden gevonden (${src.size})", src.size >= 60)
        val h = hits(src)
        assertTrue("bronbeleid geschonden:\n" + h.joinToString("\n"), h.isEmpty())
    }

    /** Deel 2: INTERNET precies één keer gevraagd, met de network-security-config ernaast. */
    @Test fun bronmanifestVraagtInternetEenKeerMetNetwerkbeleid() {
        val mf = xmlCode(File(main, "AndroidManifest.xml").readText())
        assertTrue("INTERNET-regel", mf.lines().count { it.trim() == INTERNET_LINE } == 1)
        assertTrue("INTERNET elders", Regex("permission\\.INTERNET").findAll(mf).count() == 1)
        assertTrue(mf.contains("android:networkSecurityConfig=\"@xml/network_security_config\""))
        assertTrue(mf.contains("android:usesCleartextTraffic=\"false\""))
    }

    private companion object {
        const val INTERNET_LINE = "<uses-permission android:name=\"android.permission.INTERNET\" />"
    }

    /** Zelftest: de regels vangen de verboden code echt. */
    @Test fun regelsVangenVerbodenCode() {
        val tmp = File.createTempFile("policy", ".kt")
        try {
            val bad = listOf(
                "val a = BiometricManager.Authenticators.DEVICE_CREDENTIAL",
                "val p = Manifest.permission.INTERNET",
                "Log.d(\"x\", \"pin=\$pin\")",
                "android.util.Log.i(TAG, token.toString())",
                "println(\"hallo\")",
                "e.printStackTrace()",
            )
            val h = hits(listOf(tmp to kotlinCode(bad.joinToString("\n"))))
            assertTrue("zelftest vangt niet alles: $h", h.size == bad.size)
            assertTrue(h.count { it.endsWith("log met pin/token") } == 2)
            val ok = hits(listOf(tmp to kotlinCode("// Log.d(\"pin\")\n/* DEVICE_CREDENTIAL */\nval pinLength = 63")))
            assertTrue("commentaar telt mee: $ok", ok.isEmpty())
        } finally {
            tmp.delete()
        }
    }
}
