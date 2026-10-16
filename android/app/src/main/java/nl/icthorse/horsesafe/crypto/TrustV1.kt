package nl.icthorse.horsesafe.crypto

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

/** Fout bij trust_v1. [code] = vaste reden (bv. `kh_missing`, `browser_proof_invalid`). */
class TrustException(val code: String) : Exception(code)

/**
 * Vertrouwde browser + ontgrendelverzoek (HARDWARE_KEYS §14.2), byte voor byte gelijk aan de Python-generator
 * `specs/testvectors/gen_trust_v1.py` (vectoren `trust_v1.json`) en de webkant.
 *
 * De telefoon gebruikt:
 * - [verifySigReq] VÓÓR de vinger (handtekening van de browser over [reqT] met pub_B);
 * - [verifyProof] NÁ de vinger (CK nodig; kh MOET aanwezig zijn, §11.3.7);
 * - [sealRelay] om CK alleen naar de tijdelijke browsersleutel epk_L te verzegelen (Seal_v2 purpose `relay`).
 *
 * Geheimen (k_bind, pt_ck) worden binnen deze functies na gebruik met `fill(0)` gewist.
 */
object TrustV1 {
    private const val BIND_SALT = "HSv2 bind salt"
    private const val BIND_INFO = "HSv2 browser bind"
    private const val BIND_T = "HSv2 browser"
    private const val LOGIN_T = "HSv2 blogin"
    private const val REQ_T = "HSv2 approve"
    const val NONCE_LEN = 32
    const val SIG_LEN = 64
    const val PROOF_LEN = 32

    /** Orde n van P-256 (secp256r1). */
    private val N_P256 = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    /** Tekst met "\0" tussen de delen; een deel met een nulteken is ongeldig (anders schuiven de velden). */
    private fun joined(parts: List<String>): ByteArray {
        parts.forEach { require(!it.contains('\u0000')) { "nulteken in veld" } }
        return parts.joinToString("\u0000").toByteArray(Charsets.UTF_8)
    }

    /**
     * k_bind = HKDF-SHA256(ikm = pt_ck, salt = SHA-256("HSv2 bind salt" ‖ 0x00 ‖ vault_id), info = "HSv2 browser bind", L = 32).
     * [ptCk] = exact de Seal_v2-plaintext `{"ph":…,"kh":…}`. Wordt niet gewist (dat doet de aanroeper).
     */
    fun kBind(ptCk: ByteArray, vaultId: String): ByteArray {
        val salt = MessageDigest.getInstance("SHA-256").digest(joined(listOf(BIND_SALT, vaultId)))
        return Hkdf.sha256(ptCk, salt, BIND_INFO)
    }

    /** bind_t = "HSv2 browser" ‖ \0 ‖ vault_id ‖ \0 ‖ browser_id ‖ \0 ‖ pub_B ‖ \0 ‖ label. */
    fun bindT(vaultId: String, browserId: String, pubB: String, label: String): ByteArray =
        joined(listOf(BIND_T, vaultId, browserId, pubB, label))

    /** proof = HMAC-SHA256(k_bind, bind_t). */
    fun proof(kBind: ByteArray, bindT: ByteArray): ByteArray = Hkdf.hmacSha256(kBind, bindT)

    /**
     * k_bind uit CK. Weigert als `kh` ontbreekt (§11.3.7: vertrouwen alleen bij een kluis met keyfile).
     * @throws TrustException `kh_missing`
     */
    fun kBindFor(ck: SealedSecret, vaultId: String): ByteArray {
        if (ck.kh == null) throw TrustException("kh_missing")
        val pt = SealV2.plaintext(ck.ph, ck.kh)
        try {
            return kBind(pt, vaultId)
        } finally {
            pt.fill(0)
        }
    }

    /**
     * Controleert het koppelbewijs (timing-safe). [proofB64u] = b64u van 32 bytes.
     * @return true als het bewijs klopt.
     * @throws TrustException `kh_missing` als CK geen keyfile-hash heeft (altijd weigeren).
     */
    fun verifyProof(ck: SealedSecret, vaultId: String, browserId: String, pubB: String, label: String, proofB64u: String): Boolean {
        val expected = try {
            B64u.decode(proofB64u, PROOF_LEN)
        } catch (e: IllegalArgumentException) {
            // kh-eis gaat vóór de vorm van het bewijs: zonder keyfile altijd kh_missing.
            if (ck.kh == null) throw TrustException("kh_missing")
            return false
        }
        val k = kBindFor(ck, vaultId)
        val bt = try {
            bindT(vaultId, browserId, pubB, label)
        } catch (e: IllegalArgumentException) {
            k.fill(0)
            return false
        }
        val actual = proof(k, bt)
        k.fill(0)
        try {
            return MessageDigest.isEqual(actual, expected)
        } finally {
            actual.fill(0)
        }
    }

    /** login_t = "HSv2 blogin" ‖ \0 ‖ challenge_id ‖ \0 ‖ b64u(challenge) ‖ \0 ‖ browser_id ‖ \0 ‖ email_lc (alleen ter referentie/test). */
    fun loginT(challengeId: String, challengeB64u: String, browserId: String, emailLc: String): ByteArray =
        joined(listOf(LOGIN_T, challengeId, challengeB64u, browserId, emailLc))

    /**
     * req_t = "HSv2 approve" ‖ \0 ‖ approval_id ‖ \0 ‖ vault_id ‖ \0 ‖ browser_id ‖ \0 ‖ epk_L ‖ \0 ‖ b64u(nonce_L) ‖ \0 ‖ created_at.
     * [epkL] en [nonceLB64u] zijn de b64u-strings zoals de server ze levert (canoniek gecontroleerd door de aanroeper).
     */
    fun reqT(approvalId: String, vaultId: String, browserId: String, epkL: String, nonceLB64u: String, createdAt: Long): ByteArray =
        joined(listOf(REQ_T, approvalId, vaultId, browserId, epkL, nonceLB64u, createdAt.toString()))

    /** Publieke sleutel uit pub_B (b64u van SPKI-DER); alleen P-256. null bij elke afwijking. */
    fun publicKey(pubB: String): ECPublicKey? = try {
        val der = B64u.decode(pubB)
        val k = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as? ECPublicKey
        if (k != null && k.params.order == N_P256 && k.params.curve.field.fieldSize == 256 && B64u.encode(k.encoded) == pubB) k else null
    } catch (e: IllegalArgumentException) {
        null
    } catch (e: GeneralSecurityException) {
        null
    } catch (e: ClassCastException) {
        null
    }

    /**
     * Controleert sig_req (ECDSA-P256-SHA256, raw r‖s van 64 bytes) over [reqT] met [pubB]. Nooit een uitzondering:
     * elke afwijking (sleutelvorm, lengte, r/s buiten 1..n-1) geeft false.
     */
    fun verifySigReq(pubB: String, reqT: ByteArray, sigRaw: ByteArray): Boolean {
        val key = publicKey(pubB) ?: return false
        val der = rawToDer(sigRaw) ?: return false
        return try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(reqT)
                verify(der)
            }
        } catch (e: GeneralSecurityException) {
            false
        }
    }

    /**
     * P1363 (r‖s, elk 32 bytes) → ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` voor java.security.Signature.
     * null bij een verkeerde lengte of r/s buiten 1..n-1.
     */
    fun rawToDer(raw: ByteArray): ByteArray? {
        if (raw.size != SIG_LEN) return null
        val r = BigInteger(1, raw.copyOfRange(0, 32))
        val s = BigInteger(1, raw.copyOfRange(32, 64))
        if (r.signum() <= 0 || s.signum() <= 0 || r >= N_P256 || s >= N_P256) return null
        val rb = r.toByteArray() // minimaal, met 0x00 ervoor als het hoogste bit gezet is
        val sb = s.toByteArray()
        val body = ByteArrayOutputStream()
        body.write(0x02); body.write(rb.size); body.write(rb)
        body.write(0x02); body.write(sb.size); body.write(sb)
        val b = body.toByteArray()
        val out = ByteArrayOutputStream()
        out.write(0x30)
        out.write(b.size) // max 2 × (2 + 33) = 70 < 128: korte lengtevorm
        out.write(b)
        return out.toByteArray()
    }

    /** bind voor purpose `relay` (§12.5): approval_id ‖ \0 ‖ b64u(nonce_L). */
    fun relayBind(approvalId: String, nonceLB64u: String): String {
        require(!approvalId.contains('\u0000') && !nonceLB64u.contains('\u0000')) { "nulteken in veld" }
        return approvalId + "\u0000" + nonceLB64u
    }

    /** resp = Seal_v2(epk_L, CK, "relay", vault_id, bind = approval_id ‖ \0 ‖ b64u(nonce_L)), kid = approval_id. */
    fun sealRelay(epkL: ByteArray, ck: SealedSecret, vaultId: String, approvalId: String, nonceLB64u: String): String {
        if (ck.kh == null) throw TrustException("kh_missing")
        return SealV2.seal(epkL, ck.ph, ck.kh, SealV2.PURPOSE_RELAY, vaultId, relayBind(approvalId, nonceLB64u), approvalId)
    }

    /** Deterministische variant van [sealRelay] (testingang: vaste efemere sleutel en iv). */
    internal fun sealRelayWith(
        epkL: ByteArray,
        ck: SealedSecret,
        vaultId: String,
        approvalId: String,
        nonceLB64u: String,
        ephemeralSk: ByteArray,
        iv: ByteArray,
    ): String {
        if (ck.kh == null) throw TrustException("kh_missing")
        return SealV2.sealWith(epkL, ck.ph, ck.kh, SealV2.PURPOSE_RELAY, vaultId, relayBind(approvalId, nonceLB64u), approvalId, ephemeralSk, iv)
    }
}
