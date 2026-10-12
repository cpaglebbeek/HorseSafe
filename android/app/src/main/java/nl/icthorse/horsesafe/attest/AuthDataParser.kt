package nl.icthorse.horsesafe.attest

/** authenticatorData is structureel ongeldig. */
internal class MalformedAuthDataException(message: String) : Exception(message)

/** Ontlede authenticatorData (WebAuthn §6.1) van een makeCredential-antwoord. */
internal class ParsedAuthData(
    val rpIdHash: ByteArray,
    val flags: Int,
    val signCount: Long,
    /** 16 bytes, of null als AT=0. */
    val aaguid: ByteArray?,
    val credentialId: ByteArray?,
    /** Gedecodeerde COSE-sleutel (int-sleutels als Long), of null als AT=0. */
    val coseKey: Map<Any?, Any?>?,
) {
    val up get() = flags and FLAG_UP != 0
    val uv get() = flags and FLAG_UV != 0
    val be get() = flags and FLAG_BE != 0
    val bs get() = flags and FLAG_BS != 0
    val at get() = flags and FLAG_AT != 0
    val ed get() = flags and FLAG_ED != 0

    companion object {
        const val FLAG_UP = 0x01
        const val FLAG_UV = 0x04
        const val FLAG_BE = 0x08
        const val FLAG_BS = 0x10
        const val FLAG_AT = 0x40
        const val FLAG_ED = 0x80

        /**
         * Strikt: na de COSE-sleutel (en bij ED=1 precies één extensie-map) mogen geen bytes over zijn.
         */
        fun parse(b: ByteArray): ParsedAuthData {
            if (b.size < 37) throw MalformedAuthDataException("authData te kort")
            val rpIdHash = b.copyOfRange(0, 32)
            val flags = b[32].toInt() and 0xff
            val signCount = ((b[33].toLong() and 0xff) shl 24) or ((b[34].toLong() and 0xff) shl 16) or
                ((b[35].toLong() and 0xff) shl 8) or (b[36].toLong() and 0xff)
            var pos = 37
            var aaguid: ByteArray? = null
            var credId: ByteArray? = null
            var cose: Map<Any?, Any?>? = null
            if (flags and FLAG_AT != 0) {
                if (b.size < pos + 18) throw MalformedAuthDataException("attestedCredentialData te kort")
                aaguid = b.copyOfRange(pos, pos + 16)
                pos += 16
                val len = ((b[pos].toInt() and 0xff) shl 8) or (b[pos + 1].toInt() and 0xff)
                pos += 2
                if (len == 0 || len > 1023 || b.size < pos + len) throw MalformedAuthDataException("credentialId ongeldig")
                credId = b.copyOfRange(pos, pos + len)
                pos += len
                val r = MiniCbor(b, pos)
                @Suppress("UNCHECKED_CAST")
                cose = r.read() as? Map<Any?, Any?> ?: throw MalformedAuthDataException("COSE-sleutel geen map")
                pos = r.pos
            }
            if (flags and FLAG_ED != 0) {
                val r = MiniCbor(b, pos)
                if (r.read() !is Map<*, *>) throw MalformedAuthDataException("extensies geen map")
                pos = r.pos
            }
            if (pos != b.size) throw MalformedAuthDataException("restbytes na authData")
            return ParsedAuthData(rpIdHash, flags, signCount, aaguid, credId, cose)
        }
    }
}

/**
 * Minimale, strikte CBOR-lezer voor COSE-sleutels en extensie-maps: major types 0-5 en 7 (false, true,
 * null), definite lengths, geen tags, geen floats, nesting ≤ 4. Alles anders = [MalformedAuthDataException].
 */
internal class MiniCbor(private val b: ByteArray, start: Int) {
    var pos: Int = start
        private set

    fun read(): Any? = item(0)

    private fun u8(): Int {
        if (pos >= b.size) throw MalformedAuthDataException("CBOR afgekapt")
        return b[pos++].toInt() and 0xff
    }

    private fun arg(info: Int): Long = when {
        info < 24 -> info.toLong()
        info == 24 -> u8().toLong()
        info == 25 -> ((u8() shl 8) or u8()).toLong()
        info == 26 -> (0 until 4).fold(0L) { acc, _ -> (acc shl 8) or u8().toLong() }
        info == 27 -> {
            val v = (0 until 8).fold(0L) { acc, _ -> (acc shl 8) or u8().toLong() }
            if (v < 0) throw MalformedAuthDataException("CBOR-getal te groot")
            v
        }
        else -> throw MalformedAuthDataException("CBOR: onbepaalde lengte niet toegestaan")
    }

    private fun len(info: Int): Int {
        val n = arg(info)
        if (n > b.size - pos) throw MalformedAuthDataException("CBOR-lengte buiten de data")
        return n.toInt()
    }

    private fun item(depth: Int): Any? {
        if (depth > 4) throw MalformedAuthDataException("CBOR te diep genest")
        val ib = u8()
        val major = ib ushr 5
        val info = ib and 0x1f
        return when (major) {
            0 -> arg(info)
            1 -> -1L - arg(info)
            2 -> {
                val n = len(info)
                b.copyOfRange(pos, pos + n).also { pos += n }
            }
            3 -> {
                val n = len(info)
                b.copyOfRange(pos, pos + n).decodeToString(throwOnInvalidSequence = true).also { pos += n }
            }
            4 -> {
                val n = len(info)
                List(n) { item(depth + 1) }
            }
            5 -> {
                val n = len(info)
                val m = LinkedHashMap<Any?, Any?>()
                repeat(n) {
                    val k = item(depth + 1)
                    if (k is ByteArray || k is List<*> || k is Map<*, *>) throw MalformedAuthDataException("CBOR-sleutel ongeldig")
                    if (m.containsKey(k)) throw MalformedAuthDataException("CBOR: dubbele sleutel")
                    m[k] = item(depth + 1)
                }
                m
            }
            7 -> when (info) {
                20 -> false
                21 -> true
                22 -> null
                else -> throw MalformedAuthDataException("CBOR: simple/float niet toegestaan")
            }
            else -> throw MalformedAuthDataException("CBOR: tags niet toegestaan")
        }
    }
}
