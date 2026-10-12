package nl.icthorse.horsesafe.pin

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * A-20 / A-16 voor `pin/`: geen niet-cryptografische RNG en geen bestand-, netwerk- of logcode.
 * Grep op de broncode zonder commentaar (zodat KDoc het verbod mag noemen).
 */
class PinSourcePolicyTest {
    private val dir = listOf("src/main/java/nl/icthorse/horsesafe/pin", "app/src/main/java/nl/icthorse/horsesafe/pin")
        .map(::File).first { it.isDirectory }

    private fun code(f: File): String =
        f.readText()
            .replace(Regex("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), " ")
            .replace(Regex("//[^\n]*"), " ")

    private val forbidden = listOf(
        Regex("java\\.util\\.Random\\b"),
        Regex("kotlin\\.random"),
        Regex("(?<![A-Za-z])Random\\s*[(.]"),
        Regex("(?<![A-Za-z])Random\\s*$", RegexOption.MULTILINE),
        Regex("ThreadLocalRandom|SplittableRandom|Math\\.random"),
        Regex("\\.random\\s*\\("),
        Regex("\\.shuffled\\s*\\(\\s*\\)"),
        Regex("java\\.io|java\\.nio|java\\.net|okhttp|Socket"),
        Regex("android\\.util\\.Log|println|printStackTrace|System\\.(out|err)"),
        Regex("ClipboardManager"),
        Regex("String\\s*\\(\\s*chars|concatToString|String\\.valueOf"),
    )

    @Test fun geenVerbodenApis() {
        val files = dir.walkTopDown().filter { it.isFile && it.extension == "kt" }.toList()
        assertTrue("pin/ bevat bronbestanden", files.size >= 5)
        val hits = files.flatMap { f -> val c = code(f); forbidden.filter { it.containsMatchIn(c) }.map { "${f.name}: ${it.pattern}" } }
        assertTrue("verboden in pin/: $hits", hits.isEmpty())
    }

    @Test fun generatorGebruiktSecureRandom() {
        val c = code(File(dir, "PinGenerator.kt"))
        assertTrue(c.contains("import java.security.SecureRandom"))
    }

    /** De verboden-lijst vangt echt wat hij moet vangen. */
    @Test fun regelsZijnScherp() {
        val bad = listOf("import java.util.Random", "import kotlin.random.Random", "val r = Random(1)", "Random.nextInt(3)", "list.random()", "Math.random()")
        bad.forEach { s -> assertTrue(s, forbidden.any { it.containsMatchIn(s) }) }
        val ok = listOf("SecureRandom()", "RandomSource", "SecureRandomSource(random)")
        ok.forEach { s -> assertTrue(s, forbidden.none { it.containsMatchIn(s) }) }
    }
}
