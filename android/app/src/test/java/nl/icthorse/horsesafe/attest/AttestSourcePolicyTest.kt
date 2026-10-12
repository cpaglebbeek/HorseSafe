package nl.icthorse.horsesafe.attest

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A-16 / A-18 voor `attest/`: geen bestand-, netwerk- of logcode en geen rpId `icthorsecloud.nl`.
 * Grep op de broncode zonder commentaar (KDoc mag het verbod noemen).
 */
class AttestSourcePolicyTest {
    private val dir = listOf("src/main/java/nl/icthorse/horsesafe/attest", "app/src/main/java/nl/icthorse/horsesafe/attest")
        .map(::File).first { it.isDirectory }

    private fun code(f: File): String =
        f.readText()
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
            .replace(Regex("//[^\n]*"), " ")

    private val forbidden = listOf(
        Regex("java\\.io|java\\.nio|java\\.net|okhttp|Socket|HttpURLConnection|URL\\s*\\("),
        Regex("(?<![A-Za-z])File\\s*\\(|readBytes\\s*\\(|readText\\s*\\(|openFileInput|getAssets|\\.assets\\b|AssetManager"),
        Regex("android\\.util\\.Log|(?<![A-Za-z])Log\\.[a-z]+\\s*\\(|println|printStackTrace|System\\.(out|err)"),
        Regex("icthorsecloud\\.nl"),
        Regex("PKIXRevocationChecker|isRevocationEnabled\\s*=\\s*true"),
    )

    @Test fun geenVerbodenApis() {
        val files = dir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue(files.size >= 4)
        val hits = files.flatMap { f -> val c = code(f); forbidden.filter { it.containsMatchIn(c) }.map { "${f.name}: ${it.pattern}" } }
        assertTrue("verboden in attest/: $hits", hits.isEmpty())
    }

    @Test fun revocatieStaatUit() {
        assertTrue(code(File(dir, "AttestationVerifier.kt")).contains("isRevocationEnabled = false"))
    }

    @Test fun verbodenLijstVangtWatHijMoetVangen() {
        val bad = listOf("import java.io.File", "File(\"x\")", "context.assets.open(\"a\")", "Log.d(\"x\")", "println(1)", "\"icthorsecloud.nl\"")
        bad.forEach { s -> assertTrue(s, forbidden.any { it.containsMatchIn(s) }) }
        assertTrue(forbidden.none { it.containsMatchIn("pem.inputStream()") })
    }
}
