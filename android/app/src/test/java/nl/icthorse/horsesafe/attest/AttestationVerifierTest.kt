package nl.icthorse.horsesafe.attest

import java.util.Date
import nl.icthorse.horsesafe.attest.AttestTestData.allowlist
import nl.icthorse.horsesafe.attest.AttestTestData.foreignRoots
import nl.icthorse.horsesafe.attest.AttestTestData.testRoots
import nl.icthorse.horsesafe.attest.AttestTestData.vector
import nl.icthorse.horsesafe.attest.AttestTestData.vectors
import nl.icthorse.horsesafe.attest.AttestationVerifier.Reason
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Verdict
import nl.icthorse.horsesafe.yubikey.api.AttestationEvidence
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyVariant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Synthetische vectoren uit `src/test/tools/gen_attest_vectors.py` (eigen test-CA, nooit een Yubico-root),
 * via injecteerbare [TrustRoots]. De allowlist is de echte `backend/data/aaguids.json`.
 */
class AttestationVerifierTest {
    /** Vaste tijd binnen de geldigheid van de test-CA (2025..2125) en ná het verlopen leaf (2026-01-01). */
    private val fixedNow = Date(1_780_000_000_000L) // 2026-05-28

    private fun verifier(roots: TrustRoots = testRoots, now: Date = fixedNow) =
        AttestationVerifier(roots, allowlist, clock = { now })

    private fun run(id: String, roots: TrustRoots = testRoots, now: Date = fixedNow): AttestationResult {
        val v = vector(id)
        return verifier(roots, now).verify(v.evidence, v.expectedAaguid, v.expectedClass)
    }

    private fun assertStop(id: String, stop: Stop, reason: Reason) {
        val r = run(id)
        assertTrue("$id: $r", r is AttestationResult.Failed)
        r as AttestationResult.Failed
        assertEquals(id, stop, r.stop)
        assertEquals(id, reason, r.reason)
    }

    @Test fun alleVectorenGevenHetVerwachteOordeel() {
        assertTrue(vectors.size >= 20)
        for (v in vectors) {
            val r = verifier().verify(v.evidence, v.expectedAaguid, v.expectedClass)
            if (v.expect == "OK") {
                assertTrue("${v.id}: $r", r is AttestationResult.Ok)
            } else {
                assertTrue("${v.id}: $r", r is AttestationResult.Failed)
                r as AttestationResult.Failed
                assertEquals(v.id, Stop.valueOf(v.expect), r.stop)
                assertEquals(v.id, Reason.valueOf(v.reason!!), r.reason)
            }
        }
    }

    @Test fun geldigeKetenBioMetUv() {
        val r = run("ok_bio_uv") as AttestationResult.Ok
        assertEquals("9dd8d593-2213-438a-97f8-d6b813d51c27", r.aaguid.uuid)
        assertEquals(KeyClass.BIO, r.keyClass)
        assertEquals(KeyVariant.FIDO, r.variant)
        assertEquals(AttestationVerifier.ES256, r.credentialAlg)
        assertEquals(AttestationVerifier.ES256, r.attestationAlg)
        assertTrue(r.userVerified)
        assertEquals(TrustRoots.sha256Hex(vector("ok_bio_uv").evidence.x5c[0]), r.leafSha256)
        assertEquals(Verdict.GREEN, r.toCheckResult().verdict)
    }

    @Test fun geldigeKetenYk5AlleenAanraking() {
        val r = run("ok_yk5_up_only") as AttestationResult.Ok
        assertEquals(KeyClass.YUBIKEY5, r.keyClass)
        assertFalse(r.userVerified)
    }

    @Test fun intermediateUitDeRootsPem() {
        assertTrue(run("ok_intermediate_uit_roots_pem") is AttestationResult.Ok)
    }

    @Test fun attStmtMetEdDsa() {
        assertEquals(AttestationVerifier.EDDSA, (run("ok_attstmt_eddsa") as AttestationResult.Ok).attestationAlg)
    }

    @Test fun verkeerdeCa() = assertStop("verkeerde_ca", Stop.ATTEST_CHAIN_INVALID, Reason.CHAIN)

    @Test fun geldigeKetenMaarVreemdeRootsGeinjecteerd() {
        val r = run("ok_bio_uv", roots = foreignRoots) as AttestationResult.Failed
        assertEquals(Stop.ATTEST_CHAIN_INVALID, r.stop)
        assertEquals(Reason.CHAIN, r.reason)
    }

    @Test fun geenRootsIsFailClosed() {
        val r = run("ok_bio_uv", roots = TrustRoots.EMPTY) as AttestationResult.Failed
        assertEquals(Reason.NO_TRUST_ROOTS, r.reason)
        assertEquals(Verdict.RED, r.toCheckResult().verdict)
    }

    @Test fun aaguidMismatchLeaf() = assertStop("aaguid_mismatch_leaf", Stop.ATTEST_AAGUID_MISMATCH, Reason.LEAF_AAGUID_MISMATCH)
    @Test fun aaguidMismatchGetInfo() = assertStop("aaguid_mismatch_getinfo", Stop.ATTEST_AAGUID_MISMATCH, Reason.GETINFO_AAGUID_MISMATCH)
    @Test fun leafZonderAaguid() = assertStop("leaf_zonder_aaguid", Stop.ATTEST_AAGUID_MISMATCH, Reason.LEAF_AAGUID_MISSING)
    @Test fun none() = assertStop("none_attestation", Stop.ATTEST_NOT_PACKED, Reason.NOT_PACKED)
    @Test fun self() = assertStop("self_attestation", Stop.ATTEST_NOT_PACKED, Reason.SELF_ATTESTATION)
    @Test fun be1() = assertStop("be_1", Stop.ATTEST_FLAGS_INVALID, Reason.NOT_DEVICE_BOUND)
    @Test fun bs1() = assertStop("bs_1", Stop.ATTEST_FLAGS_INVALID, Reason.NOT_DEVICE_BOUND)
    @Test fun uv0MetToken() = assertStop("uv_0_met_token", Stop.ATTEST_FLAGS_INVALID, Reason.UV_MISSING)
    @Test fun verkeerdeHandtekening() = assertStop("verkeerde_handtekening", Stop.ATTEST_CHAIN_INVALID, Reason.SIGNATURE)
    @Test fun verkeerdeRpId() = assertStop("verkeerde_rp_id", Stop.ATTEST_RP_ID_HASH, Reason.RP_ID)
    @Test fun leafIsCa() = assertStop("leaf_is_ca", Stop.ATTEST_CHAIN_INVALID, Reason.LEAF_IS_CA)
    @Test fun credentialNietEs256() = assertStop("credential_eddsa", Stop.ATTEST_ALGORITHM, Reason.CREDENTIAL_ALG)
    @Test fun attStmtRs256() = assertStop("attstmt_rs256", Stop.ATTEST_ALGORITHM, Reason.ATTESTATION_ALG)
    @Test fun nietOpLijst() = assertStop("aaguid_niet_op_lijst", Stop.AAGUID_NOT_ALLOWED, Reason.NOT_ALLOWED)
    @Test fun klassePastNiet() = assertStop("klasse_past_niet", Stop.CLASS_MISMATCH, Reason.CLASS_MISMATCH)

    @Test fun verlopenLeafIsAlleenFoutNaDeEinddatum() {
        assertStop("leaf_verlopen", Stop.ATTEST_CHAIN_INVALID, Reason.CHAIN)
        assertTrue(run("leaf_verlopen", now = Date(1_750_000_000_000L)) is AttestationResult.Ok) // 2025-06
    }

    @Test fun uv0ZonderTokenMagAlleenBijWithTokenFalse() {
        // Zelfde bytes als uv_0_met_token, maar als "alleen aanraking" aangeboden: dan is UV=0 toegestaan.
        val v = vector("uv_0_met_token")
        val e = v.evidence
        val asTouch = AttestationEvidence(e.fmt, e.authData, e.alg, e.sig, e.x5c, e.clientDataHash, e.rpId, withToken = false)
        assertTrue(verifier().verify(asTouch, v.expectedAaguid, v.expectedClass) is AttestationResult.Ok)
    }

    @Test fun anderClientDataHashBreektDeHandtekening() {
        val v = vector("ok_bio_uv")
        val e = v.evidence
        val other = e.clientDataHash.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val r = verifier().verify(
            AttestationEvidence(e.fmt, e.authData, e.alg, e.sig, e.x5c, other, e.rpId, e.withToken),
            v.expectedAaguid, v.expectedClass,
        ) as AttestationResult.Failed
        assertEquals(Reason.SIGNATURE, r.reason)
    }

    @Test fun andereRpIdInEvidenceWordtGeweigerd() {
        val v = vector("ok_bio_uv")
        val e = v.evidence
        val r = verifier().verify(
            AttestationEvidence(e.fmt, e.authData, e.alg, e.sig, e.x5c, e.clientDataHash, "icthorse.invalid", e.withToken),
            v.expectedAaguid, v.expectedClass,
        ) as AttestationResult.Failed
        assertEquals(Stop.ATTEST_RP_ID_HASH, r.stop)
    }

    @Test fun kapotCertificaatInX5c() {
        val v = vector("ok_bio_uv")
        val e = v.evidence
        val r = verifier().verify(
            AttestationEvidence(e.fmt, e.authData, e.alg, e.sig, listOf(byteArrayOf(0x30, 0x03, 0x01)), e.clientDataHash, e.rpId, e.withToken),
            v.expectedAaguid, v.expectedClass,
        ) as AttestationResult.Failed
        assertEquals(Stop.ATTEST_CHAIN_INVALID, r.stop)
    }

    @Test fun toStringVanEvidenceEnResultaatBevatGeenBytes() {
        val r = run("ok_bio_uv").toString()
        assertFalse(r.contains("[B@"))
    }
}
