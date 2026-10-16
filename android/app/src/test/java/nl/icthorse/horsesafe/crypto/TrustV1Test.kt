package nl.icthorse.horsesafe.crypto

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPrivateKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * trust_v1-vectoren (HARDWARE_KEYS §14.2, `specs/testvectors/trust_v1.json`, generator `gen_trust_v1.py`):
 * k_bind/bind_t/proof (beide vectoren + negatief), login_t, req_t byte voor byte, sig_req (positief en
 * negatief) en relay verzegelen byte voor byte met de vaste efemere sleutel/iv van de generator + openen.
 */
class TrustV1Test {
    private val data = Vectors.load("trust_v1.json")
    private val proofs = Vectors.list(data, "proof_vectors")

    @Suppress("UNCHECKED_CAST")
    private val approval = data["approval_vector"] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    private val login = data["login_vector"] as Map<String, Any?>
    private val negative = Vectors.list(data, "negative")

    private fun b(s: Any?): ByteArray = B64u.decode(s as String)
    private fun bOrNull(s: Any?): ByteArray? = (s as String?)?.let { B64u.decode(it) }
    private fun ck(v: Map<String, Any?>) = SealedSecret(bOrNull(v["ph"]), bOrNull(v["kh"]))
    private fun neg(name: String): Map<*, *> = negative.single { it["name"] == name }["change"] as Map<*, *>

    /** Zelfde `det()` als de generator: SHA-256("HorseSafe testvector:<label>:<i>") aaneengeregen. */
    private fun det(label: String, n: Int = 32): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        var i = 0
        while (out.size() < n) {
            out.write(MessageDigest.getInstance("SHA-256").digest("HorseSafe testvector:$label:$i".toByteArray()))
            i++
        }
        return out.toByteArray().copyOf(n)
    }

    private fun reqT(change: Map<*, *> = emptyMap<String, Any>()): ByteArray = TrustV1.reqT(
        approval["approval_id"] as String,
        approval["vault_id"] as String,
        approval["browser_id"] as String,
        approval["epk_l"] as String,
        approval["nonce_l"] as String,
        (change["created_at"] ?: approval["created_at"]) as Long,
    )

    @Test fun formaat() {
        assertEquals("HorseSafe trust_v1 testvectors", data["format"])
        assertEquals(listOf("ph+kh", "alleen kh"), proofs.map { it["name"] })
        assertEquals(6, negative.size)
    }

    @Test fun kBindBindTEnProofBeideVectoren() {
        proofs.forEach { v ->
            val name = v["name"]
            val pt = SealV2.plaintext(bOrNull(v["ph"]), bOrNull(v["kh"]))
            assertEquals("$name pt_ck", v["pt_ck"], String(pt, Charsets.UTF_8))
            val k = TrustV1.kBind(pt, v["vault_id"] as String)
            assertEquals("$name k_bind", v["k_bind_hex"], Vectors.hex(k))
            assertEquals("$name k_bind via CK", v["k_bind_hex"], Vectors.hex(TrustV1.kBindFor(ck(v), v["vault_id"] as String)))
            val t = TrustV1.bindT(v["vault_id"] as String, v["browser_id"] as String, v["pub_b"] as String, v["label"] as String)
            assertEquals("$name bind_t", v["bind_t_hex"], Vectors.hex(t))
            assertEquals("$name proof", v["proof"], B64u.encode(TrustV1.proof(k, t)))
            assertTrue(
                "$name verifyProof",
                TrustV1.verifyProof(ck(v), v["vault_id"] as String, v["browser_id"] as String, v["pub_b"] as String, v["label"] as String, v["proof"] as String),
            )
        }
    }

    @Test fun proofNegatief() {
        val v = proofs.single { it["name"] == "ph+kh" }
        fun check(vault: String = v["vault_id"] as String, label: String = v["label"] as String, pub: String = v["pub_b"] as String, proof: String = v["proof"] as String) =
            TrustV1.verifyProof(ck(v), vault, v["browser_id"] as String, pub, label, proof)
        assertTrue(check())
        assertFalse("ander vault_id", check(vault = neg("ander vault_id")["vault_id"] as String))
        assertFalse("ander label", check(label = neg("ander label")["label"] as String))
        assertFalse("andere pub_b", check(pub = neg("andere pub_b")["pub_b"] as String))
        assertFalse("andere browser_id", TrustV1.verifyProof(ck(v), v["vault_id"] as String, "00000000-0000-4000-8000-000000000001", v["pub_b"] as String, v["label"] as String, v["proof"] as String))
        // Bewijs van de andere vector (alleen kh) hoort niet bij ph+kh.
        assertFalse("proof van andere CK", check(proof = proofs.single { it["name"] == "alleen kh" }["proof"] as String))
        // Vorm: geen 32 bytes of geen b64u → false, geen uitzondering.
        assertFalse("kort bewijs", check(proof = "AAAA"))
        assertFalse("geen b64u", check(proof = "c8Gy8julmSkOwh06CVrqq1Nj7806jBEQGClTTxR+kt4"))
        // Eén bit anders.
        val flipped = b(v["proof"]).also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse("bit omgedraaid", check(proof = B64u.encode(flipped)))
    }

    @Test fun khNullWordtGeweigerd() {
        val v = proofs.single { it["name"] == "ph+kh" }
        assertNull(neg("kh null")["kh"])
        val noKh = SealedSecret(bOrNull(v["ph"]), null)
        listOf(
            { TrustV1.verifyProof(noKh, v["vault_id"] as String, v["browser_id"] as String, v["pub_b"] as String, v["label"] as String, v["proof"] as String) },
            { TrustV1.verifyProof(noKh, v["vault_id"] as String, v["browser_id"] as String, v["pub_b"] as String, v["label"] as String, "AAAA") },
            { TrustV1.kBindFor(noKh, v["vault_id"] as String) },
            { TrustV1.sealRelay(ByteArray(32) { 9 }, noKh, "v", "a", "n") },
        ).forEach { f ->
            try {
                f()
                fail("kh=null moet geweigerd worden")
            } catch (e: TrustException) {
                assertEquals("kh_missing", e.code)
            }
        }
    }

    @Test fun loginT() {
        val t = TrustV1.loginT(login["challenge_id"] as String, login["challenge"] as String, login["browser_id"] as String, login["email_lc"] as String)
        assertEquals(login["login_t_hex"], Vectors.hex(t))
        assertTrue("login-handtekening (P1363) klopt", TrustV1.verifySigReq(login["pub_b"] as String, t, b(login["sig"])))
    }

    @Test fun reqTByteVoorByte() {
        assertEquals(approval["req_t_hex"], Vectors.hex(reqT()))
        assertEquals(1792150000L, approval["created_at"])
    }

    @Test fun sigReqPositief() {
        assertTrue(TrustV1.verifySigReq(approval["pub_b"] as String, reqT(), b(approval["sig_req"])))
    }

    @Test fun sigReqNegatief() {
        val pub = approval["pub_b"] as String
        val sig = b(approval["sig_req"])
        assertFalse("ander created_at", TrustV1.verifySigReq(pub, reqT(neg("ander created_at")), sig))
        // Elk veld van req_t telt mee.
        val other = TrustV1.reqT(approval["approval_id"] as String, approval["vault_id"] as String, approval["browser_id"] as String,
            approval["epk_l"] as String, neg("andere nonce bij openen")["nonce_l"] as String, approval["created_at"] as Long)
        assertFalse("andere nonce", TrustV1.verifySigReq(pub, other, sig))
        val bad = sig.copyOf().also { it[63] = (it[63].toInt() xor 1).toByte() }
        assertFalse("gewijzigde handtekening", TrustV1.verifySigReq(pub, reqT(), bad))
        assertFalse("63 bytes", TrustV1.verifySigReq(pub, reqT(), sig.copyOf(63)))
        assertFalse("r = 0", TrustV1.verifySigReq(pub, reqT(), ByteArray(32) + sig.copyOfRange(32, 64)))
        assertFalse("s = n", TrustV1.verifySigReq(pub, reqT(), sig.copyOfRange(0, 32) + Vectors.hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")))
        assertFalse("andere sleutel", TrustV1.verifySigReq(neg("andere pub_b")["pub_b"] as String, reqT(), sig))
        assertFalse("onzin-sleutel", TrustV1.verifySigReq("AAAA", reqT(), sig))
    }

    @Test fun derConversieTegenJcaHandtekening() {
        // Eigen handtekening met de vaste browsersleutel (DER van de JCA → raw → terug) moet rond gaan.
        val d = BigInteger(data["browser_key"].let { (it as Map<*, *>)["d_hex"] as String }, 16)
        val pub = TrustV1.publicKey(approval["pub_b"] as String) as ECPublicKey
        val priv = KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(d, pub.params))
        repeat(20) {
            val der = Signature.getInstance("SHA256withECDSA").run { initSign(priv); update(reqT()); sign() }
            val raw = derToRaw(der)
            assertArrayEquals(der, TrustV1.rawToDer(raw))
            assertTrue(TrustV1.verifySigReq(approval["pub_b"] as String, reqT(), raw))
        }
        assertNotNull(TrustV1.publicKey(approval["pub_b"] as String))
        assertNull("geen P-256-SPKI", TrustV1.publicKey(neg("andere pub_b")["pub_b"] as String))
    }

    @Test fun relayVerzegelenByteVoorByte() {
        val epkL = b(approval["epk_l"])
        assertEquals("epk_L uit e_L", approval["epk_l"], B64u.encode(X25519.publicKey(b(approval["e_l_sk"]))))
        assertEquals("relay_bind", approval["relay_bind"], TrustV1.relayBind(approval["approval_id"] as String, approval["nonce_l"] as String))
        val aad = SealV2.aad(SealV2.PURPOSE_RELAY, approval["vault_id"] as String, approval["relay_bind"] as String)
        assertEquals("relay_aad", approval["relay_aad_hex"], Vectors.hex(aad))
        val resp = TrustV1.sealRelayWith(
            epkL, ck(approval), approval["vault_id"] as String, approval["approval_id"] as String, approval["nonce_l"] as String,
            det("trust:relay:e"), det("trust:relay:iv", 12),
        )
        assertEquals("resp", approval["resp"], resp)
    }

    @Test fun relayOpenenEnNegatief() {
        val eL = b(approval["e_l_sk"])
        val vault = approval["vault_id"] as String
        val aid = approval["approval_id"] as String
        val nonce = approval["nonce_l"] as String
        // Vector-resp én een vers (willekeurig) verzegeld antwoord gaan open met e_L.
        val fresh = TrustV1.sealRelay(b(approval["epk_l"]), ck(approval), vault, aid, nonce)
        listOf(approval["resp"] as String, fresh).forEach { resp ->
            val s = SealV2.open(resp, eL, SealV2.PURPOSE_RELAY, vault, aid, TrustV1.relayBind(aid, nonce))
            assertArrayEquals(b(approval["ph"]), s.ph)
            assertArrayEquals(b(approval["kh"]), s.kh)
            s.wipe()
        }
        val otherNonce = neg("andere nonce bij openen")["nonce_l"] as String
        listOf(
            { SealV2.open(approval["resp"] as String, eL, SealV2.PURPOSE_RELAY, vault, aid, TrustV1.relayBind(aid, otherNonce)) },
            { SealV2.open(approval["resp"] as String, eL, SealV2.PURPOSE_STORE, vault, aid, TrustV1.relayBind(aid, nonce)) },
            { SealV2.open(approval["resp"] as String, eL, SealV2.PURPOSE_RELAY, "00000000-0000-4000-8000-000000000000", aid, TrustV1.relayBind(aid, nonce)) },
        ).forEach { f ->
            try {
                f()
                fail("moet unseal_failed geven")
            } catch (e: SealException) {
                assertEquals("unseal_failed", e.code)
            }
        }
    }

    @Test fun nultekenInVeldWordtGeweigerd() {
        try {
            TrustV1.bindT("a\u0000b", "c", "d", "e")
            fail()
        } catch (e: IllegalArgumentException) {
            // verwacht
        }
    }

    /** DER (SEQUENCE{INTEGER r, INTEGER s}) → raw r‖s (alleen voor deze test). */
    private fun derToRaw(der: ByteArray): ByteArray {
        var p = 2
        fun int(): ByteArray {
            check(der[p] == 0x02.toByte())
            val len = der[p + 1].toInt()
            val v = der.copyOfRange(p + 2, p + 2 + len)
            p += 2 + len
            val trimmed = v.dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(32 - trimmed.size) + trimmed
        }
        return int() + int()
    }
}
