package nl.icthorse.horsesafe.attest

import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertPathValidator
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.util.Date
import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Verdict
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.AttestationEvidence
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyVariant

/** Uitkomst van [AttestationVerifier.verify]. Bevat geen credentialId of publieke sleutel (A-21). */
sealed class AttestationResult {
    data class Ok(
        val aaguid: Aaguid,
        val keyClass: KeyClass,
        val variant: KeyVariant,
        /** SHA-256 (kleine-letter-hex) van het leafcertificaat (DER), voor het rapport. */
        val leafSha256: String,
        val credentialAlg: Int,
        val attestationAlg: Int,
        val userVerified: Boolean,
    ) : AttestationResult()

    data class Failed(val stop: Stop, val reason: AttestationVerifier.Reason) : AttestationResult()

    fun toCheckResult(): CheckResult = when (this) {
        is Ok -> CheckResult(CHECK_ID, Verdict.GREEN, "Echtheid bewezen (packed, keten tot vertrouwde root, AAGUID klopt).")
        is Failed -> CheckResult(CHECK_ID, Verdict.RED, stop.tekst)
    }

    companion object {
        const val CHECK_ID = "attestation"
    }
}

/**
 * Kotlin-port van de attestation-stappen van `backend/services/webauthn_service.py` (`verify_create`
 * stap 4-8, `_leaf_aaguid`, py_webauthn `verify_packed` + `validate_certificate_chain`), toegepast op de
 * keurings-credential ([AttestOps.KEURING_RP_ID]). Puur: geen netwerk, geen bestanden, geen revocatie.
 *
 * Controles, in deze volgorde (de eerste fout bepaalt de [Stop]):
 * 1. `fmt == packed`, met `sig`, `alg` en een niet-lege `x5c`. `none`, self-attestation (packed zonder x5c)
 *    of een ander format → [Stop.ATTEST_NOT_PACKED].
 * 2. authenticatorData strikt ontleden; kapot → [Stop.ATTEST_FLAGS_INVALID] (reden MALFORMED_AUTH_DATA).
 * 3. rpIdHash == SHA-256([AttestOps.KEURING_RP_ID]) en `evidence.rpId` is die rpId → [Stop.ATTEST_RP_ID_HASH].
 * 4. Vlaggen: UP=1; UV=1 als de credential met een token is gemaakt (`withToken`, YK5 vóór setPin heeft
 *    geen UV-eis); BE=0 en BS=0 (alleen device-bound); AT=1 → [Stop.ATTEST_FLAGS_INVALID].
 * 5. Credential-algoritme (COSE `alg`, met passende kty/crv) in [allowedCredentialAlgs] (standaard alleen
 *    ES256, de keuring vraagt `[-7]`) en attStmt-`alg` in [allowedAttestationAlgs] (ES256, EdDSA; de server
 *    accepteert beide) en passend bij de leafsleutel → [Stop.ATTEST_ALGORITHM].
 * 6. Keten: pad bouwen van het leaf via `x5c[1..]` en de intermediates uit [TrustRoots] naar een
 *    zelf-ondertekende anchor, daarna `CertPathValidator` (PKIX, revocatie uit, tijd = [clock]). Geen
 *    ankers = fail-closed. Leaf met BasicConstraints CA=true is ongeldig → [Stop.ATTEST_CHAIN_INVALID].
 * 7. Handtekening `sig` over `authData ‖ clientDataHash` met de leafsleutel → [Stop.ATTEST_CHAIN_INVALID]
 *    (reden SIGNATURE).
 * 8. Leaf-extensie 1.3.6.1.4.1.45724.1.1.4 (extnValue = `04 10` + 16 bytes) == AAGUID in authData ==
 *    [verify]`.expectedAaguid` (uit de verse getInfo) → [Stop.ATTEST_AAGUID_MISMATCH].
 * 9. Allowlist: niet op de lijst → [Stop.AAGUID_NOT_ALLOWED]; klasse ≠ verwachte klasse →
 *    [Stop.CLASS_MISMATCH].
 */
class AttestationVerifier(
    private val trustRoots: TrustRoots,
    private val allowlist: AaguidAllowlist,
    private val allowedCredentialAlgs: Set<Int> = setOf(ES256),
    private val allowedAttestationAlgs: Set<Int> = setOf(ES256, EDDSA),
    private val clock: () -> Date = { Date() },
) {

    /** Reden van afwijzing; [serverCode] is de foutcode die `webauthn_service.verify_create` zou geven. */
    enum class Reason(val serverCode: String) {
        NOT_PACKED("attestation_invalid"),
        SELF_ATTESTATION("attestation_invalid"),
        MISSING_SIG_OR_ALG("attestation_invalid"),
        MALFORMED_AUTH_DATA("bad_authenticator_data"),
        RP_ID("rp_id_mismatch"),
        UP_MISSING("up_missing"),
        UV_MISSING("uv_missing"),
        NOT_DEVICE_BOUND("not_device_bound"),
        AT_MISSING("bad_authenticator_data"),
        CREDENTIAL_ALG("alg_not_allowed"),
        ATTESTATION_ALG("attestation_invalid"),
        NO_TRUST_ROOTS("attestation_invalid"),
        BAD_CERTIFICATE("attestation_invalid"),
        CHAIN("attestation_invalid"),
        LEAF_IS_CA("attestation_invalid"),
        SIGNATURE("attestation_invalid"),
        LEAF_AAGUID_MISSING("attestation_invalid"),
        LEAF_AAGUID_MISMATCH("attestation_invalid"),
        GETINFO_AAGUID_MISMATCH("attestation_invalid"),
        NOT_ALLOWED("authenticator_not_allowed"),
        CLASS_MISMATCH("not_bio_authenticator"),
    }

    private class Fail(val stop: Stop, val reason: Reason) : Exception(null, null, false, false)

    /**
     * @param expectedAaguid AAGUID uit de verse getInfo van dezelfde sleutel.
     * @param expectedClass klasse die het profiel eist ([nl.icthorse.horsesafe.flow.Profile.keyClass]).
     */
    fun verify(evidence: AttestationEvidence, expectedAaguid: Aaguid, expectedClass: KeyClass): AttestationResult =
        try {
            check(evidence, expectedAaguid, expectedClass)
        } catch (f: Fail) {
            AttestationResult.Failed(f.stop, f.reason)
        } catch (e: RuntimeException) {
            // Onverwacht (bv. kapotte sleutelparameters): fail-closed, zonder details.
            AttestationResult.Failed(Stop.ATTEST_CHAIN_INVALID, Reason.BAD_CERTIFICATE)
        }

    private fun fail(stop: Stop, reason: Reason): Nothing = throw Fail(stop, reason)

    private fun check(ev: AttestationEvidence, expectedAaguid: Aaguid, expectedClass: KeyClass): AttestationResult.Ok {
        // 1 — format
        if (ev.fmt != FMT_PACKED) fail(Stop.ATTEST_NOT_PACKED, Reason.NOT_PACKED)
        if (ev.x5c.isEmpty()) fail(Stop.ATTEST_NOT_PACKED, Reason.SELF_ATTESTATION)
        val attAlg = ev.alg ?: fail(Stop.ATTEST_NOT_PACKED, Reason.MISSING_SIG_OR_ALG)
        if (ev.sig.isEmpty()) fail(Stop.ATTEST_NOT_PACKED, Reason.MISSING_SIG_OR_ALG)

        // 2 — authData
        val ad = try {
            ParsedAuthData.parse(ev.authData)
        } catch (e: MalformedAuthDataException) {
            fail(Stop.ATTEST_FLAGS_INVALID, Reason.MALFORMED_AUTH_DATA)
        } catch (e: CharacterCodingException) {
            fail(Stop.ATTEST_FLAGS_INVALID, Reason.MALFORMED_AUTH_DATA)
        }

        // 3 — rpIdHash
        val expectedHash = MessageDigest.getInstance("SHA-256").digest(AttestOps.KEURING_RP_ID.toByteArray(Charsets.UTF_8))
        if (ev.rpId != AttestOps.KEURING_RP_ID || !MessageDigest.isEqual(ad.rpIdHash, expectedHash)) {
            fail(Stop.ATTEST_RP_ID_HASH, Reason.RP_ID)
        }

        // 4 — vlaggen
        if (!ad.up) fail(Stop.ATTEST_FLAGS_INVALID, Reason.UP_MISSING)
        if (ev.withToken && !ad.uv) fail(Stop.ATTEST_FLAGS_INVALID, Reason.UV_MISSING)
        if (ad.be || ad.bs) fail(Stop.ATTEST_FLAGS_INVALID, Reason.NOT_DEVICE_BOUND)
        val cose = ad.coseKey
        val authAaguid = ad.aaguid
        if (!ad.at || cose == null || authAaguid == null) fail(Stop.ATTEST_FLAGS_INVALID, Reason.AT_MISSING)

        // 5 — algoritmes
        val credAlg = coseAlg(cose) ?: fail(Stop.ATTEST_ALGORITHM, Reason.CREDENTIAL_ALG)
        if (credAlg !in allowedCredentialAlgs) fail(Stop.ATTEST_ALGORITHM, Reason.CREDENTIAL_ALG)
        if (attAlg !in allowedAttestationAlgs) fail(Stop.ATTEST_ALGORITHM, Reason.ATTESTATION_ALG)

        // 6 — keten
        if (trustRoots.isEmpty) fail(Stop.ATTEST_CHAIN_INVALID, Reason.NO_TRUST_ROOTS)
        val certs = try {
            val cf = CertificateFactory.getInstance("X.509")
            ev.x5c.map { cf.generateCertificate(it.inputStream()) as X509Certificate }
        } catch (e: CertificateException) {
            fail(Stop.ATTEST_CHAIN_INVALID, Reason.BAD_CERTIFICATE)
        } catch (e: ClassCastException) {
            fail(Stop.ATTEST_CHAIN_INVALID, Reason.BAD_CERTIFICATE)
        }
        val leaf = certs[0]
        if (leaf.basicConstraints != -1) fail(Stop.ATTEST_CHAIN_INVALID, Reason.LEAF_IS_CA)
        if (!keyMatchesAlg(leaf.publicKey, attAlg)) fail(Stop.ATTEST_ALGORITHM, Reason.ATTESTATION_ALG)
        validateChain(leaf, certs.drop(1))

        // 7 — handtekening
        if (!signatureValid(leaf.publicKey, attAlg, ev.authData + ev.clientDataHash, ev.sig)) {
            fail(Stop.ATTEST_CHAIN_INVALID, Reason.SIGNATURE)
        }

        // 8 — AAGUID
        val leafAaguid = leafAaguid(leaf) ?: fail(Stop.ATTEST_AAGUID_MISMATCH, Reason.LEAF_AAGUID_MISSING)
        if (!MessageDigest.isEqual(leafAaguid, authAaguid)) fail(Stop.ATTEST_AAGUID_MISMATCH, Reason.LEAF_AAGUID_MISMATCH)
        val aaguid = Aaguid(uuidString(authAaguid))
        if (aaguid != expectedAaguid) fail(Stop.ATTEST_AAGUID_MISMATCH, Reason.GETINFO_AAGUID_MISMATCH)

        // 9 — allowlist en klasse
        val entry = allowlist.lookup(aaguid) ?: fail(Stop.AAGUID_NOT_ALLOWED, Reason.NOT_ALLOWED)
        if (entry.keyClass != expectedClass) fail(Stop.CLASS_MISMATCH, Reason.CLASS_MISMATCH)

        return AttestationResult.Ok(
            aaguid = aaguid,
            keyClass = entry.keyClass,
            variant = entry.variant,
            leafSha256 = TrustRoots.sha256Hex(ev.x5c[0]),
            credentialAlg = credAlg,
            attestationAlg = attAlg,
            userVerified = ad.uv,
        )
    }

    /** Bouwt een pad leaf → … → anchor (diepte-eerst, max [MAX_PATH] intermediates) en valideert het met PKIX. */
    private fun validateChain(leaf: X509Certificate, fromX5c: List<X509Certificate>) {
        val pool = (fromX5c + trustRoots.intermediates).distinct()
        val paths = ArrayList<List<X509Certificate>>()
        fun build(path: List<X509Certificate>) {
            if (paths.size >= MAX_CANDIDATE_PATHS) return
            val cur = path.last()
            if (trustRoots.anchors.any { a ->
                    a.trustedCert.subjectX500Principal == cur.issuerX500Principal && verifies(cur, a.trustedCert.publicKey)
                }
            ) {
                paths.add(path)
            }
            if (path.size > MAX_PATH) return
            for (c in pool) {
                if (c in path) continue
                if (c.subjectX500Principal == cur.issuerX500Principal && verifies(cur, c.publicKey)) build(path + c)
            }
        }
        build(listOf(leaf))
        if (paths.isEmpty()) fail(Stop.ATTEST_CHAIN_INVALID, Reason.CHAIN)
        val cf = CertificateFactory.getInstance("X.509")
        val validator = CertPathValidator.getInstance("PKIX")
        for (p in paths) {
            try {
                val params = PKIXParameters(trustRoots.anchors.toSet()).apply {
                    isRevocationEnabled = false
                    date = clock()
                }
                validator.validate(cf.generateCertPath(p), params)
                return
            } catch (e: Exception) {
                // volgend kandidaatpad
            }
        }
        fail(Stop.ATTEST_CHAIN_INVALID, Reason.CHAIN)
    }

    private fun verifies(c: X509Certificate, key: PublicKey): Boolean = try {
        c.verify(key)
        true
    } catch (e: Exception) {
        false
    }

    companion object {
        const val ES256 = -7
        const val EDDSA = -8
        const val FMT_PACKED = "packed"
        const val AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4"
        private const val MAX_PATH = 4
        private const val MAX_CANDIDATE_PATHS = 8

        /** COSE `alg` (sleutel 3), alleen als kty/crv erbij passen; anders null. */
        internal fun coseAlg(cose: Map<Any?, Any?>): Int? {
            val alg = (cose[3L] as? Long)?.toInt() ?: return null
            val kty = cose[1L] as? Long
            val crv = cose[-1L] as? Long
            return when (alg) {
                ES256 -> if (kty == 2L && crv == 1L && (cose[-2L] as? ByteArray)?.size == 32 &&
                    (cose[-3L] as? ByteArray)?.size == 32
                ) alg else null
                EDDSA -> if (kty == 1L && crv == 6L && (cose[-2L] as? ByteArray)?.size == 32) alg else null
                else -> alg // onbekend algoritme: laat de allowlist-controle het afwijzen
            }
        }

        internal fun keyMatchesAlg(key: PublicKey, alg: Int): Boolean = when (alg) {
            ES256 -> key is ECPublicKey && key.params.curve.field.fieldSize == 256
            EDDSA -> key.algorithm == "EdDSA" || key.algorithm == "Ed25519"
            else -> false
        }

        internal fun signatureValid(key: PublicKey, alg: Int, data: ByteArray, sig: ByteArray): Boolean = try {
            val s = when (alg) {
                ES256 -> Signature.getInstance("SHA256withECDSA")
                EDDSA -> Signature.getInstance("Ed25519")
                else -> return false
            }
            s.initVerify(key)
            s.update(data)
            s.verify(sig)
        } catch (e: Exception) {
            false
        }

        /**
         * Port van `_leaf_aaguid`: `getExtensionValue` geeft de DER-OCTET STRING om extnValue heen, dus
         * verwacht exact `04 12 04 10` + 16 bytes. Anders null.
         */
        internal fun leafAaguid(leaf: X509Certificate): ByteArray? {
            val v = leaf.getExtensionValue(AAGUID_OID) ?: return null
            if (v.size != 20 || v[0] != 0x04.toByte() || v[1] != 0x12.toByte() ||
                v[2] != 0x04.toByte() || v[3] != 0x10.toByte()
            ) return null
            return v.copyOfRange(4, 20)
        }

        internal fun uuidString(b: ByteArray): String {
            val h = b.joinToString("") { "%02x".format(it) }
            return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
        }
    }
}
