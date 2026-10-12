package nl.icthorse.horsesafe.report

/**
 * Kleine, strikte JSON-lezer en -schrijver voor rapporten (geen externe bibliotheek; org.json is in
 * JVM-tests niet beschikbaar en is bovendien niet strikt).
 *
 * Lezen (RFC 8259, strenger):
 * - alleen objecten, arrays, strings, `true`/`false`/`null` en GEHELE getallen (geen breuk/exponent);
 * - dubbele sleutels, ongeldige escapes, ongepaarde surrogaten, stuurtekens in strings, tekst na het
 *   einde en nesting dieper dan [MAX_DEPTH] → [ReportSchemaException];
 * - resultaat: `Map<String, Any?>` (volgorde behouden), `List<Any?>`, `String`, `Long`, `Boolean`, `null`.
 *
 * Schrijven: deterministisch, puur ASCII (alles buiten 0x20..0x7e als `\uXXXX`).
 */
internal object StrictJson {
    const val MAX_DEPTH = 8

    fun parse(text: String): Any? {
        val p = Parser(text)
        p.ws()
        val v = p.value(0)
        p.ws()
        if (p.pos != text.length) throw err("tekst na het einde van het JSON-document")
        return v
    }

    fun write(value: Any?): String = StringBuilder().also { writeTo(it, value) }.toString()

    private fun writeTo(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is Int, is Long -> sb.append(v.toString())
            is String -> writeString(sb, v)
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, value) in v) {
                    if (k !is String) throw err("sleutel is geen string")
                    if (!first) sb.append(',')
                    first = false
                    writeString(sb, k)
                    sb.append(':')
                    writeTo(sb, value)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                v.forEachIndexed { i, e ->
                    if (i > 0) sb.append(',')
                    writeTo(sb, e)
                }
                sb.append(']')
            }
            else -> throw err("type niet toegestaan in rapport-JSON: ${v::class.java.simpleName}")
        }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c.code in 0x20..0x7e -> sb.append(c)
                else -> sb.append("\\u").append(String.format("%04x", c.code))
            }
        }
        sb.append('"')
    }

    private fun err(msg: String) = ReportSchemaException(msg)

    private class Parser(val s: String) {
        var pos = 0

        fun ws() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++
        }

        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) throw err("JSON te diep genest")
            if (pos >= s.length) throw err("onverwacht einde van JSON")
            return when (val c = s[pos]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> lit("true", true)
                'f' -> lit("false", false)
                'n' -> lit("null", null)
                else -> if (c == '-' || c in '0'..'9') num() else throw err("onverwacht teken in JSON op positie $pos")
            }
        }

        private fun lit(word: String, v: Any?): Any? {
            if (!s.startsWith(word, pos)) throw err("ongeldig woord in JSON op positie $pos")
            pos += word.length
            return v
        }

        private fun num(): Long {
            val start = pos
            if (s[pos] == '-') pos++
            if (pos >= s.length) throw err("ongeldig getal")
            if (s[pos] == '0') {
                pos++
            } else if (s[pos] in '1'..'9') {
                while (pos < s.length && s[pos] in '0'..'9') pos++
            } else {
                throw err("ongeldig getal")
            }
            if (pos < s.length && (s[pos] == '.' || s[pos] == 'e' || s[pos] == 'E')) throw err("alleen gehele getallen toegestaan")
            val text = s.substring(start, pos)
            if (text.length > 19) throw err("getal te groot")
            return text.toLongOrNull() ?: throw err("getal te groot")
        }

        private fun str(): String {
            pos++ // "
            val sb = StringBuilder()
            while (true) {
                if (pos >= s.length) throw err("string niet afgesloten")
                val c = s[pos++]
                when {
                    c == '"' -> break
                    c == '\\' -> {
                        if (pos >= s.length) throw err("string niet afgesloten")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000c')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) throw err("ongeldige \\u-escape")
                                val hex = s.substring(pos, pos + 4)
                                if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw err("ongeldige \\u-escape")
                                sb.append(hex.toInt(16).toChar())
                                pos += 4
                            }
                            else -> throw err("ongeldige escape \\$e")
                        }
                    }
                    c.code < 0x20 -> throw err("stuurteken in string")
                    else -> sb.append(c)
                }
            }
            val out = sb.toString()
            // Surrogaten moeten correct gepaard zijn.
            var i = 0
            while (i < out.length) {
                val ch = out[i]
                if (ch.isHighSurrogate()) {
                    if (i + 1 >= out.length || !out[i + 1].isLowSurrogate()) throw err("ongepaard surrogaat")
                    i += 2
                } else if (ch.isLowSurrogate()) {
                    throw err("ongepaard surrogaat")
                } else {
                    i++
                }
            }
            return out
        }

        private fun obj(depth: Int): Map<String, Any?> {
            pos++ // {
            val m = LinkedHashMap<String, Any?>()
            ws()
            if (pos < s.length && s[pos] == '}') { pos++; return m }
            while (true) {
                ws()
                if (pos >= s.length || s[pos] != '"') throw err("sleutel verwacht")
                val k = str()
                ws()
                if (pos >= s.length || s[pos] != ':') throw err("':' verwacht")
                pos++
                ws()
                if (m.containsKey(k)) throw err("dubbele sleutel '$k'")
                m[k] = value(depth + 1)
                ws()
                if (pos >= s.length) throw err("object niet afgesloten")
                when (s[pos++]) {
                    ',' -> continue
                    '}' -> return m
                    else -> throw err("',' of '}' verwacht")
                }
            }
        }

        private fun arr(depth: Int): List<Any?> {
            pos++ // [
            val l = ArrayList<Any?>()
            ws()
            if (pos < s.length && s[pos] == ']') { pos++; return l }
            while (true) {
                ws()
                l += value(depth + 1)
                ws()
                if (pos >= s.length) throw err("array niet afgesloten")
                when (s[pos++]) {
                    ',' -> continue
                    ']' -> return l
                    else -> throw err("',' of ']' verwacht")
                }
            }
        }

        private fun err(msg: String) = ReportSchemaException(msg)
    }
}
