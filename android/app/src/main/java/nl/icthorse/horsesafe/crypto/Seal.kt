package nl.icthorse.horsesafe.crypto

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import nl.icthorse.horsesafe.report.ReportSchemaException
import nl.icthorse.horsesafe.report.StrictJson

/** Fout bij Seal_v2. [code] is de vaste code uit §12.5: `unseal_failed` of `invalid_sealed`. */
class SealException(val code: String) : Exception(code)

/**
 * Ontgrendelmateriaal CK = {ph, kh} (§2): elk 32 bytes of null, minstens één niet-null.
 * Bevat geheimen: altijd [wipe] na gebruik; [toString] toont niets.
 */
class SealedSecret(val ph: ByteArray?, val kh: ByteArray?) {
    fun wipe() {
        ph?.fill(0)
        kh?.fill(0)
    }

    override fun toString(): String = "SealedSecret([verborgen])"
}

/**
 * Seal_v2 (HARDWARE_KEYS §12.5), byte voor byte gelijk aan `frontend/js/hwkeys.js` en de Python-referentie
 * (vectoren `specs/testvectors/seal_v2.json`).
 *
 * In de app is alleen [open] nodig (proef "Kopie openen", §13.3 stap 6). [sealWith]/[seal] bestaan voor de
 * vectortests en als referentie; de app verzegelt zelf niets.
 */
object SealV2 {
    const val VERSION = 2
    const val PURPOSE_STORE = "store"
    const val PURPOSE_RELAY = "relay"
    private const val INFO = "HorseSafe v2 seal"
    private const val IV_LEN = 12
    private const val TAG_BITS = 128
    private const val MAX_SEALED = 1024
    private val SEALED_KEYS = listOf("v", "kid", "epk", "iv", "ct")

    /** AAD = "HSv2" 0x00 purpose 0x00 vault_id 0x00 bind. */
    fun aad(purpose: String, vaultId: String, bind: String): ByteArray {
        val out = ByteArrayOutputStream()
        listOf("HSv2", purpose, vaultId, bind).forEachIndexed { i, part ->
            if (i > 0) out.write(0)
            out.write(part.toByteArray(Charsets.UTF_8))
        }
        return out.toByteArray()
    }

    /** k = HKDF-SHA256(ikm=ss, salt=epk‖P, info="HorseSafe v2 seal", L=32). */
    fun sealKey(ss: ByteArray, epk: ByteArray, recipientPk: ByteArray): ByteArray =
        Hkdf.sha256(ss, epk + recipientPk, INFO)

    /** pt = exact `{"ph":<v>,"kh":<v>}` (deze volgorde, geen spaties). */
    fun plaintext(ph: ByteArray?, kh: ByteArray?): ByteArray {
        require(ph != null || kh != null) { "ph en kh zijn allebei leeg" }
        require(ph == null || ph.size == 32) { "ph moet 32 bytes zijn" }
        require(kh == null || kh.size == 32) { "kh moet 32 bytes zijn" }
        fun v(b: ByteArray?) = if (b == null) "null" else "\"" + B64u.encode(b) + "\""
        return "{\"ph\":${v(ph)},\"kh\":${v(kh)}}".toByteArray(Charsets.UTF_8)
    }

    /** Verzegelen met een nieuwe efemere sleutel en iv. */
    fun seal(recipientPk: ByteArray, ph: ByteArray?, kh: ByteArray?, purpose: String, vaultId: String, bind: String, kid: String): String {
        val rnd = SecureRandom()
        val e = X25519.newPrivate(rnd)
        val iv = ByteArray(IV_LEN).also { rnd.nextBytes(it) }
        try {
            return sealWith(recipientPk, ph, kh, purpose, vaultId, bind, kid, e, iv)
        } finally {
            e.fill(0)
        }
    }

    /** Deterministisch verzegelen (testingang, zelfde rol als `_crypto.sealWith` in hwkeys.js). */
    fun sealWith(
        recipientPk: ByteArray,
        ph: ByteArray?,
        kh: ByteArray?,
        purpose: String,
        vaultId: String,
        bind: String,
        kid: String,
        ephemeralSk: ByteArray,
        iv: ByteArray,
    ): String {
        require(iv.size == IV_LEN) { "iv moet 12 bytes zijn" }
        val epk = X25519.publicKey(ephemeralSk)
        val ss = X25519.sharedSecret(ephemeralSk, recipientPk)
        val k = sealKey(ss, epk, recipientPk)
        ss.fill(0)
        val pt = plaintext(ph, kh)
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(TAG_BITS, iv))
            c.updateAAD(aad(purpose, vaultId, bind))
            val ct = c.doFinal(pt)
            val obj = linkedMapOf<String, Any?>(
                "v" to VERSION, "kid" to kid, "epk" to B64u.encode(epk), "iv" to B64u.encode(iv), "ct" to B64u.encode(ct),
            )
            return StrictJson.write(obj)
        } finally {
            k.fill(0)
            pt.fill(0)
        }
    }

    /** Vormcontrole zoals `validate_sealed` op de server (§12.5), plus de lengtes na decoderen. */
    internal class Parsed(val kid: String, val epk: ByteArray, val iv: ByteArray, val ct: ByteArray)

    internal fun parse(sealed: String): Parsed {
        if (sealed.length > MAX_SEALED) throw SealException("invalid_sealed")
        val obj = try {
            StrictJson.parse(sealed)
        } catch (e: ReportSchemaException) {
            throw SealException("invalid_sealed")
        } as? Map<*, *> ?: throw SealException("invalid_sealed")
        if (obj.keys.toList().sortedBy { it.toString() } != SEALED_KEYS.sorted()) throw SealException("invalid_sealed")
        if (obj["v"] != VERSION.toLong()) throw SealException("invalid_sealed")
        val kid = obj["kid"] as? String ?: throw SealException("invalid_sealed")
        val epkS = obj["epk"] as? String ?: throw SealException("invalid_sealed")
        val ivS = obj["iv"] as? String ?: throw SealException("invalid_sealed")
        val ctS = obj["ct"] as? String ?: throw SealException("invalid_sealed")
        if (epkS.length != 43 || ivS.length != 16 || ctS.length !in 40..400) throw SealException("invalid_sealed")
        return try {
            Parsed(kid, B64u.decode(epkS, 32), B64u.decode(ivS, IV_LEN), B64u.decode(ctS))
        } catch (e: IllegalArgumentException) {
            throw SealException("invalid_sealed")
        }
    }

    /**
     * Openen (§12.5 "Openen"): de AAD komt uit de VERWACHTE [vaultId] en [keyId] (nooit alleen uit
     * `sealed.kid`); `v == 2` en `kid == keyId` worden gecontroleerd. Elke cryptografische fout, een andere
     * kid en een onjuiste pt-vorm geven `unseal_failed`. [sk] wordt niet gewist (dat doet de aanroeper).
     */
    fun open(sealed: String, sk: ByteArray, purpose: String, vaultId: String, keyId: String): SealedSecret {
        val p = parse(sealed)
        if (p.kid != keyId) throw SealException("unseal_failed")
        val pk: ByteArray
        val ss: ByteArray
        try {
            pk = X25519.publicKey(sk)
            ss = X25519.sharedSecret(sk, p.epk)
        } catch (e: IllegalArgumentException) {
            throw SealException("unseal_failed")
        }
        val k = sealKey(ss, p.epk, pk)
        ss.fill(0)
        val pt: ByteArray = try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(TAG_BITS, p.iv))
            c.updateAAD(aad(purpose, vaultId, keyId))
            c.doFinal(p.ct)
        } catch (e: AEADBadTagException) {
            throw SealException("unseal_failed")
        } catch (e: java.security.GeneralSecurityException) {
            throw SealException("unseal_failed")
        } finally {
            k.fill(0)
        }
        try {
            return parsePlaintext(pt)
        } finally {
            pt.fill(0)
        }
    }

    /**
     * Strikte vorm van pt: exact `{"ph":<v>,"kh":<v>}` met <v> = `null` of `"<43 tekens b64u>"`
     * (32 bytes), minstens één niet-null. Werkt op bytes, zonder String met het geheim te maken.
     */
    internal fun parsePlaintext(pt: ByteArray): SealedSecret {
        var pos = 0
        fun expect(lit: String) {
            val b = lit.toByteArray(Charsets.US_ASCII)
            if (pos + b.size > pt.size) throw SealException("unseal_failed")
            for (i in b.indices) if (pt[pos + i] != b[i]) throw SealException("unseal_failed")
            pos += b.size
        }
        fun value(): ByteArray? {
            if (pos < pt.size && pt[pos] == 'n'.code.toByte()) {
                expect("null")
                return null
            }
            expect("\"")
            if (pos + 43 >= pt.size) throw SealException("unseal_failed")
            val chars = CharArray(43) { pt[pos + it].toInt().toChar() }
            pos += 43
            expect("\"")
            try {
                return decodeChars(chars)
            } finally {
                chars.fill('\u0000')
            }
        }
        expect("{\"ph\":")
        val ph = value()
        val kh: ByteArray?
        try {
            expect(",\"kh\":")
            kh = value()
            expect("}")
            if (pos != pt.size) throw SealException("unseal_failed")
        } catch (e: SealException) {
            ph?.fill(0)
            throw e
        }
        if (ph == null && kh == null) throw SealException("unseal_failed")
        return SealedSecret(ph, kh)
    }

    /** b64u-decodering van 43 tekens naar 32 bytes, canoniek, zonder tussenliggende String. */
    private fun decodeChars(c: CharArray): ByteArray {
        fun v(ch: Char): Int = when (ch) {
            in 'A'..'Z' -> ch - 'A'
            in 'a'..'z' -> ch - 'a' + 26
            in '0'..'9' -> ch - '0' + 52
            '-' -> 62
            '_' -> 63
            else -> throw SealException("unseal_failed")
        }
        val out = ByteArray(32)
        var acc = 0
        var bits = 0
        var o = 0
        for (ch in c) {
            acc = (acc shl 6) or v(ch)
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out[o++] = (acc shr bits).toByte()
                acc = acc and ((1 shl bits) - 1)
            }
        }
        // 43 tekens = 258 bits: 2 bits over, die moeten 0 zijn (canoniek).
        if (o != 32 || acc != 0) {
            out.fill(0)
            throw SealException("unseal_failed")
        }
        return out
    }
}
