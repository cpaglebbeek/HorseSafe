package nl.icthorse.horsesafe.net

import java.security.MessageDigest
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.report.StrictJson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Montgomery-uitbreiding van de device-API (§14.6) tegen een nep-transport: paden, getekende body, strikte vorm. */
class DeviceApiApprovalTest {
    private val dev = "5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d"
    private val aid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    private val vid = "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"
    private val kid = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a"
    private val bid = "7d3c2b1a-0f9e-4d8c-b7a6-5e4d3c2b1a09"

    /** Tekent de boodschap als "sig" = SHA-256(boodschap), zodat de test kan nagaan wat getekend is. */
    private val signer = DevKeySigner { MessageDigest.getInstance("SHA-256").digest(it) }

    private class Fake(val reply: (HttpRequest) -> HttpResponse) : HttpTransport {
        val seen = mutableListOf<HttpRequest>()
        override fun execute(req: HttpRequest): HttpResponse {
            seen += req
            return reply(req)
        }
    }

    private fun b64(n: Int) = B64u.encode(ByteArray(n) { (it + 1).toByte() })

    private fun detail(change: Map<String, Any?> = emptyMap(), browserChange: Map<String, Any?> = emptyMap()): String {
        val browser = linkedMapOf<String, Any?>("browser_id" to bid, "pub_B" to b64(91), "label" to "Chrome – laptop", "proof" to b64(32))
        browserChange.forEach { (k, v) -> if (v == REMOVE) browser.remove(k) else browser[k] = v }
        val m = linkedMapOf<String, Any?>(
            "approval_id" to aid, "vault_id" to vid, "vault_name" to "Database", "key_id" to kid, "browser" to browser,
            "epk_L" to b64(32), "nonce_L" to b64(32), "created_at" to 1792150000L, "sig_req" to b64(64), "ip" to "203.0.113.7",
            "ua" to "Mozilla/5.0", "requested_at" to 1792150001L, "expires_at" to 1792150120L,
        )
        change.forEach { (k, v) -> if (v == REMOVE) m.remove(k) else m[k] = v }
        return StrictJson.write(m)
    }

    private fun verifySignedBody(req: HttpRequest, path: String) {
        val msg = DeviceAuth.message(req.method, "/api$path", req.headers["X-HS-Ts"]!!.toLong(), req.headers["X-HS-Nonce"]!!, req.body ?: ByteArray(0))
        assertEquals("getekend over methode, pad en body", B64u.encode(MessageDigest.getInstance("SHA-256").digest(msg)), req.headers["X-HS-Sig"])
    }

    @Test fun statusMetWaitEnApprovals() {
        val t = Fake {
            HttpResponse(200, "{\"device_id\":\"$dev\",\"state\":\"active\",\"keys\":[],\"approvals\":[{\"approval_id\":\"$aid\",\"vault_id\":\"$vid\"}]}")
        }
        val s = DeviceApi(t).status(dev, signer, waitSeconds = 25)
        assertEquals(listOf(PendingApproval(aid, vid)), s.approvals)
        val req = t.seen.single()
        assertEquals("/device/v1/status?wait=25", req.path)
        assertTrue("leestijd ruim boven 25 s", req.readTimeoutMs!! >= 30_000)
        verifySignedBody(req, "/device/v1/status?wait=25")
    }

    @Test fun statusZonderApprovalsVeldIsLeeg() {
        val t = Fake { HttpResponse(200, "{\"device_id\":\"$dev\",\"state\":\"active\",\"keys\":[]}") }
        val s = DeviceApi(t).status(dev, signer)
        assertEquals(emptyList<PendingApproval>(), s.approvals)
        assertEquals("/device/v1/status", t.seen.single().path)
        assertNull(t.seen.single().readTimeoutMs)
    }

    @Test fun statusMetFouteApprovalsIsBadResponse() {
        listOf(
            "\"approvals\":{}",
            "\"approvals\":[{\"approval_id\":\"x\",\"vault_id\":\"$vid\"}]",
            "\"approvals\":[{\"approval_id\":\"$aid\"}]",
        ).forEach { extra ->
            try {
                DeviceApi(Fake { HttpResponse(200, "{\"device_id\":\"$dev\",\"state\":\"active\",\"keys\":[],$extra}") }).status(dev, signer)
                fail(extra)
            } catch (e: ApiException) {
                assertEquals("bad_response", e.code)
            }
        }
    }

    @Test fun waitBuitenBereikWordtGeweigerd() {
        try {
            DeviceApi(Fake { HttpResponse(200, "") }).status(dev, signer, waitSeconds = 26)
            fail()
        } catch (e: IllegalArgumentException) {
            // verwacht
        }
    }

    @Test fun approvalDetailWordtStriktGelezen() {
        val t = Fake { HttpResponse(200, detail()) }
        val r = DeviceApi(t).approval(dev, aid, signer)
        assertEquals(aid, r.approvalId)
        assertEquals(vid, r.vaultId)
        assertEquals(kid, r.keyId)
        assertEquals(TrustedBrowser(bid, b64(91), "Chrome – laptop", b64(32)), r.browser)
        assertEquals(1792150000L, r.createdAt)
        assertEquals("203.0.113.7", r.ip)
        assertEquals(1792150001L, r.requestedAt)
        assertEquals("Database", r.vaultName)
        assertEquals(1792150120L, r.expiresAt)
        val req = t.seen.single()
        assertEquals("GET", req.method)
        assertEquals("/device/v1/approvals/$aid", req.path)
        verifySignedBody(req, "/device/v1/approvals/$aid")
    }

    @Test fun approvalZonderIpUaRequestedAtMag() {
        val r = DeviceApi(Fake { HttpResponse(200, detail(mapOf("ip" to null, "ua" to REMOVE, "requested_at" to REMOVE, "vault_name" to REMOVE, "expires_at" to REMOVE, "approval_id" to REMOVE))) }).approval(dev, aid, signer)
        assertNull(r.ip)
        assertNull(r.ua)
        assertNull(r.requestedAt)
    }

    @Test fun approvalMetAfwijkendeVormIsBadResponse() {
        listOf(
            detail(mapOf("vault_id" to "geen-uuid")),
            detail(mapOf("key_id" to REMOVE)),
            detail(mapOf("epk_L" to b64(31))),
            detail(mapOf("nonce_L" to b64(16))),
            detail(mapOf("epk_l" to b64(32), "epk_L" to REMOVE)),
            detail(mapOf("approval_id" to "11111111-2222-4333-8444-555555555555")),
            detail(mapOf("expires_at" to "later")),
            detail(mapOf("vault_name" to "x".repeat(257))),
            detail(mapOf("sig_req" to b64(70))),
            detail(mapOf("sig_req" to B64u.encode(ByteArray(64)) + "=")),
            detail(mapOf("created_at" to "1792150000")),
            detail(mapOf("created_at" to 0L)),
            detail(mapOf("browser" to REMOVE)),
            detail(mapOf("ip" to 5L)),
            detail(mapOf("ua" to "x".repeat(513))),
            detail(browserChange = mapOf("label" to "")),
            detail(browserChange = mapOf("label" to "x".repeat(65))),
            detail(browserChange = mapOf("proof" to b64(31))),
            detail(browserChange = mapOf("pub_B" to "+++")),
            detail(browserChange = mapOf("pub_b" to b64(91), "pub_B" to REMOVE)),
            detail(browserChange = mapOf("browser_id" to "ABC")),
            "[]",
        ).forEach { body ->
            try {
                DeviceApi(Fake { HttpResponse(200, body) }).approval(dev, aid, signer)
                fail(body)
            } catch (e: ApiException) {
                assertEquals(body, "bad_response", e.code)
            }
        }
    }

    @Test fun approval404GeeftApiException() {
        try {
            DeviceApi(Fake { HttpResponse(404, "{\"detail\":{\"error\":\"not_found\"}}") }).approval(dev, aid, signer)
            fail()
        } catch (e: ApiException) {
            assertEquals(404, e.status)
            assertEquals("not_found", e.code)
        }
    }

    @Test fun beslissingBodiesEnHandtekening() {
        val t = Fake { HttpResponse(if (it.body!!.size > 40) 200 else 204, "") }
        val api = DeviceApi(t)
        api.decide(dev, aid, ApprovalDecision.Approve("{\"v\":2}"), signer)
        api.decide(dev, aid, ApprovalDecision.Deny(), signer)
        api.decide(dev, aid, ApprovalDecision.Deny("sig_req_invalid"), signer)
        api.decide(dev, aid, ApprovalDecision.DenyRevoke(), signer)
        assertEquals(
            listOf(
                "{\"decision\":\"approve\",\"resp\":\"{\\\"v\\\":2}\"}",
                "{\"decision\":\"deny\"}",
                "{\"decision\":\"deny\",\"reason\":\"sig_req_invalid\"}",
                "{\"decision\":\"deny_revoke\"}",
            ),
            t.seen.map { String(it.body!!, Charsets.UTF_8) },
        )
        t.seen.forEach {
            assertEquals("POST", it.method)
            assertEquals("/device/v1/approvals/$aid", it.path)
            verifySignedBody(it, "/device/v1/approvals/$aid")
        }
    }

    @Test fun beslissing409() {
        try {
            DeviceApi(Fake { HttpResponse(409, "{\"detail\":{\"error\":\"approval_not_pending\"}}") }).decide(dev, aid, ApprovalDecision.Deny(), signer)
            fail()
        } catch (e: ApiException) {
            assertEquals(409, e.status)
            assertEquals("approval_not_pending", e.code)
        }
    }

    @Test fun geenUuidGeenVerzoek() {
        val t = Fake { HttpResponse(200, detail()) }
        listOf("../x", "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5D", "").forEach { id ->
            try {
                DeviceApi(t).approval(dev, id, signer)
                fail(id)
            } catch (e: IllegalArgumentException) {
                // verwacht
            }
        }
        assertTrue(t.seen.isEmpty())
    }

    @Test fun approveToStringToontGeenResp() {
        assertEquals("Approve([verzegeld])", ApprovalDecision.Approve("geheim-ct").toString())
    }

    private companion object {
        val REMOVE = Any()
    }
}
