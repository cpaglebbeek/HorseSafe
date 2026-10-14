package nl.icthorse.horsesafe.crypto

import java.io.File
import nl.icthorse.horsesafe.report.StrictJson

/** Leest de gedeelde testvectoren uit `specs/testvectors/` (repo-root; tests draaien vanuit app/ of android/). */
internal object Vectors {
    fun load(name: String): Map<*, *> {
        val f = listOf("../../specs/testvectors/$name", "../specs/testvectors/$name").map(::File).firstOrNull { it.isFile }
            ?: error("specs/testvectors/$name niet gevonden")
        return StrictJson.parse(f.readText(Charsets.UTF_8)) as Map<*, *>
    }

    fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    @Suppress("UNCHECKED_CAST")
    fun list(m: Map<*, *>, k: String): List<Map<String, Any?>> = m[k] as List<Map<String, Any?>>
}
