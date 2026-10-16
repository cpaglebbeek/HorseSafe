package nl.icthorse.horsesafe.approval

import java.io.File
import java.nio.file.Files
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.Signature
import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.crypto.SealV2
import nl.icthorse.horsesafe.crypto.Vectors
import nl.icthorse.horsesafe.crypto.TrustV1
import nl.icthorse.horsesafe.crypto.X25519
import nl.icthorse.horsesafe.keystore.KeySlot
import nl.icthorse.horsesafe.net.ApprovalWire
import nl.icthorse.horsesafe.net.DeviceApi
import nl.icthorse.horsesafe.net.DeviceAuth
import nl.icthorse.horsesafe.net.DeviceKey
import nl.icthorse.horsesafe.net.HttpRequest
import nl.icthorse.horsesafe.net.HttpResponse
import nl.icthorse.horsesafe.net.HttpTransport
import nl.icthorse.horsesafe.pairing.DeviceRecord
import nl.icthorse.horsesafe.pairing.DeviceStore
import nl.icthorse.horsesafe.pairing.FakeFinger
import nl.icthorse.horsesafe.pairing.FakeKeys
import nl.icthorse.horsesafe.pairing.FingerStep
import nl.icthorse.horsesafe.pairing.LocalState
import nl.icthorse.horsesafe.pairing.PairFixture
import nl.icthorse.horsesafe.pairing.PairingError
import nl.icthorse.horsesafe.report.StrictJson
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.security.spec.X509EncodedKeySpec

/** Nep-server voor §14.5 stap 3-5: status met approvals, verzoekdetail, eigen kopie, beslissing. Controleert D. */
internal class FakeApprovalServer(private val keys: FakeKeys, private val pkC: ByteArray) : HttpTransport {
    @Suppress("UNCHECKED_CAST")
    val vector = Vectors.load("trust_v1.json")["approval_vector"] as Map<String, Any?>

    @Suppress("UNCHECKED_CAST")
    val proofVector = Vectors.list(Vectors.load("trust_v1.json"), "proof_vectors").single { it["name"] == "ph+kh" }
    val approvalId = vector["approval_id"] as String

    /** Aanpasbaar detail (om te manipuleren). */
    val detail: MutableMap<String, Any?> = linkedMapOf(
        "approval_id" to vector["approval_id"],
        "vault_id" to vector["vault_id"],
        "vault_name" to "Database (laptop)",
        "key_id" to PairFixture.KEY_ID,
        "browser" to linkedMapOf(
            "browser_id" to vector["browser_id"],
            "pub_B" to vector["pub_b"],
            "label" to proofVector["label"],
            "proof" to proofVector["proof"],
        ),
        "epk_L" to vector["epk_l"],
        "nonce_L" to vector["nonce_l"],
        "created_at" to vector["created_at"],
        "sig_req" to vector["sig_req"],
        "ip" to "203.0.113.7",
        "ua" to "Mozilla/5.0 (X11; Linux x86_64) Chrome/141",
        "requested_at" to (vector["created_at"] as Long) + 1,
        "expires_at" to (vector["created_at"] as Long) + 120,
    )

    @Suppress("UNCHECKED_CAST")
    val browser get() = detail["browser"] as MutableMap<String, Any?>

    var copyPh: ByteArray? = B64u.decode(vector["ph"] as String)
    var copyKh: ByteArray? = B64u.decode(vector["kh"] as String)
    var state = "active"
    var decideStatus = 200
    val decisions = mutableListOf<Map<*, *>>()
    val paths = mutableListOf<String>()

    override fun execute(req: HttpRequest): HttpResponse {
        paths += req.method + " " + req.path
        verifyDev(req)
        val dev = PairFixture.DEVICE_ID
        return when {
            req.path == "/device/v1/status?wait=25" -> {
                assertTrue("long-poll leestijd", (req.readTimeoutMs ?: 0) > 25_000)
                HttpResponse(200, StrictJson.write(linkedMapOf(
                    "device_id" to dev, "state" to state,
                    "keys" to listOf(linkedMapOf("key_id" to PairFixture.KEY_ID, "vault_id" to PairFixture.VAULT_ID, "label" to "Database")),
                    "approvals" to listOf(linkedMapOf("approval_id" to approvalId, "vault_id" to vector["vault_id"])),
                )))
            }
            req.path == "/device/v1/approvals/$approvalId" && req.method == "GET" -> HttpResponse(200, StrictJson.write(detail))
            req.path == "/device/v1/approvals/$approvalId" && req.method == "POST" -> {
                decisions += StrictJson.parse(String(req.body!!, Charsets.UTF_8)) as Map<*, *>
                if (decideStatus == 200) HttpResponse(200, "{\"approval_id\":\"$approvalId\",\"status\":\"approved\"}") else HttpResponse(decideStatus, "{\"detail\":{\"error\":\"approval_not_pending\"}}")
            }
            req.path == "/device/v1/keys/${PairFixture.KEY_ID}/sealed" -> {
                val sealed = SealV2.seal(pkC, copyPh, copyKh, "store", PairFixture.VAULT_ID, PairFixture.KEY_ID, PairFixture.KEY_ID)
                HttpResponse(200, StrictJson.write(linkedMapOf("key_id" to PairFixture.KEY_ID, "vault_id" to PairFixture.VAULT_ID, "sealed" to sealed)))
            }
            else -> HttpResponse(404, "{\"detail\":{\"error\":\"not_found\"}}")
        }
    }

    private fun verifyDev(req: HttpRequest) {
        val h = req.headers
        assertEquals(PairFixture.DEVICE_ID, h["X-HS-Device"])
        val msg = DeviceAuth.message(req.method, "/api" + req.path, h["X-HS-Ts"]!!.toLong(), h["X-HS-Nonce"]!!, req.body ?: ByteArray(0))
        val pub = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(keys.devPub(KeySlot.A)!!))
        val ok = Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(msg); verify(B64u.decode(h["X-HS-Sig"]!!)) }
        assertTrue("device-handtekening", ok)
    }
}

/** ApprovalFlow end-to-end met nep-Keystore, nep-vinger en nep-server (geen netwerk, nooit productie). */
class ApprovalFlowTest {
    private lateinit var dir: File
    private val keys = FakeKeys()
    private val finger = FakeFinger()
    private lateinit var server: FakeApprovalServer
    private lateinit var flow: ApprovalFlow
    private var wiped = 0
    private var now = 0L

    @Before fun setUp() {
        dir = Files.createTempDirectory("hs-appr").toFile()
        keys.create(ByteArray(32), KeySlot.A)
        val skC = X25519.newPrivate(SecureRandom())
        val pkC = X25519.publicKey(skC)
        val wrap = keys.wrapCipher(KeySlot.A)
        val ct = wrap.doFinal(skC)
        DeviceStore(dir).save(
            DeviceRecord(PairFixture.DEVICE_ID, LocalState.ACTIVE, "123456", "Fold", wrap.iv, ct,
                listOf(DeviceKey(PairFixture.KEY_ID, PairFixture.VAULT_ID, "Database")), 0, KeySlot.A),
        )
        server = FakeApprovalServer(keys, pkC)
        now = (server.vector["created_at"] as Long) * 1000 + 30_000
        flow = ApprovalFlow(keys, finger, DeviceApi(server, clockSeconds = { now / 1000 }), DeviceStore(dir), { wiped++ }, { now })
    }

    @After fun tearDown() {
        dir.deleteRecursively()
    }

    private fun card(): ApprovalCard = flow.load(flow.poll().single())

    @Test fun goedkeurenLevertRelayDieDeBrowserOpent() = runBlocking {
        val c = card()
        assertEquals(CardTrust.SIGNED, c.trust)
        assertEquals("Chrome – laptop", c.browserLabel)
        assertEquals("Database (laptop)", c.vaultLabel)
        assertEquals("203.0.113.7", c.request.ip)
        assertTrue("nog geen vinger vóór goedkeuren", finger.steps.isEmpty())
        assertEquals(ApproveOutcome.Approved, flow.approve(c))
        assertEquals(listOf(FingerStep.APPROVE), finger.steps)
        val d = server.decisions.single()
        assertEquals(setOf("decision", "resp"), d.keys)
        assertEquals("approve", d["decision"])
        // De browser opent het antwoord met e_L en krijgt exact CK.
        val v = server.vector
        val opened = SealV2.open(d["resp"] as String, B64u.decode(v["e_l_sk"] as String), "relay", v["vault_id"] as String,
            server.approvalId, TrustV1.relayBind(server.approvalId, v["nonce_l"] as String))
        assertArrayEquals(B64u.decode(v["ph"] as String), opened.ph)
        assertArrayEquals(B64u.decode(v["kh"] as String), opened.kh)
        assertEquals(0, wiped)
    }

    @Test fun ongeldigeHandtekeningWeigertVoorDeVinger() {
        server.detail["created_at"] = (server.vector["created_at"] as Long) + 1
        val c = card()
        assertEquals(CardTrust.SIG_INVALID, c.trust)
        assertFalse(c.canApprove)
        assertTrue(c.autoDenied)
        assertEquals(mapOf("decision" to "deny", "reason" to "sig_req_invalid"), server.decisions.single())
        assertTrue("geen vinger gevraagd", finger.steps.isEmpty())
        assertFalse("geen kopie opgehaald", server.paths.any { it.contains("/sealed") })
        try {
            runBlocking { flow.approve(c) }
            fail("niet goedkeurbaar")
        } catch (e: IllegalArgumentException) {
            // verwacht
        }
    }

    @Test fun gewijzigdLabelFaaltOpProofNaDeVinger() = runBlocking {
        // label staat niet in req_t: handtekening blijft geldig, het koppelbewijs niet.
        server.browser["label"] = "Ander apparaat"
        val c = card()
        assertEquals(CardTrust.SIGNED, c.trust)
        assertEquals(ApproveOutcome.Rejected("browser_proof_invalid"), flow.approve(c))
        assertEquals(listOf(FingerStep.APPROVE), finger.steps)
        assertEquals(mapOf("decision" to "deny", "reason" to "browser_proof_invalid"), server.decisions.single())
    }

    @Test fun anderePubBFaaltAlOpHandtekening() {
        server.browser["pub_B"] = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE" + "A".repeat(86)
        assertEquals(CardTrust.SIG_INVALID, card().trust)
    }

    @Test fun kopieZonderKeyfileWordtGeweigerd() = runBlocking {
        server.copyKh = null
        val c = card()
        assertEquals(ApproveOutcome.Rejected("keyfile_required"), flow.approve(c))
        assertEquals(mapOf("decision" to "deny", "reason" to "keyfile_required"), server.decisions.single())
    }

    @Test fun annulerenBijDeVingerBeslistNiets() {
        finger.cancelAt = FingerStep.APPROVE
        val c = card()
        try {
            runBlocking { flow.approve(c) }
            fail()
        } catch (e: IllegalStateException) {
            // nep-vinger: geannuleerd
        }
        assertTrue(server.decisions.isEmpty())
    }

    @Test fun weigerenEnIntrekken() {
        val c = card()
        flow.deny(c, revoke = false)
        flow.deny(c, revoke = true)
        assertEquals(listOf(mapOf("decision" to "deny"), mapOf("decision" to "deny_revoke")), server.decisions)
        assertTrue(finger.steps.isEmpty())
    }

    @Test fun alBeslistGeeftGone() {
        server.decideStatus = 409
        val c = card()
        try {
            flow.deny(c, revoke = false)
            fail()
        } catch (e: ApprovalError.Gone) {
            // verwacht
        }
    }

    @Test fun verlopenVerzoekIsNietGoedkeurbaar() {
        now += ApprovalFlow.MAX_AGE_S * 1000
        val c = card()
        assertEquals(CardTrust.EXPIRED, c.trust)
        assertFalse(c.canApprove)
        assertTrue(server.decisions.isEmpty())
    }

    @Test fun voorbijExpiresAtIsNietGoedkeurbaar() {
        server.detail["expires_at"] = (server.vector["created_at"] as Long) + 10 // klok staat op created_at + 30
        assertEquals(CardTrust.EXPIRED, card().trust)
    }

    @Test fun zonderVaultNameDeEigenKopienaam() {
        server.detail.remove("vault_name")
        assertEquals("Database", card().vaultLabel)
    }

    @Test fun onbekendeKopieIsNietGoedkeurbaar() {
        server.detail["key_id"] = "11111111-2222-4333-8444-555555555555"
        assertEquals(CardTrust.NO_COPY, card().trust)
    }

    @Test fun labelMetOpmaaktekensIsNietGoedkeurbaar() {
        server.browser["label"] = "Chrome‮potpal"
        assertEquals(CardTrust.LABEL_INVALID, card().trust)
    }

    @Test fun andereKluisInDetailDanInStatusWordtGeweigerd() {
        server.detail["vault_id"] = "00000000-0000-4000-8000-000000000000"
        try {
            card()
            fail()
        } catch (e: PairingError.Api) {
            assertEquals("bad_response", e.code)
        }
    }

    @Test fun ingetrokkenToestelWistLokaal() {
        server.state = "revoked"
        try {
            flow.poll()
            fail()
        } catch (e: PairingError.Revoked) {
            assertEquals(1, wiped)
        }
    }

    @Test fun ongeldigeSleutelsWissenLokaal() {
        val c = card()
        keys.invalid = true
        try {
            runBlocking { flow.approve(c) }
            fail()
        } catch (e: PairingError.KeysInvalidated) {
            assertEquals(1, wiped)
        }
        assertTrue(server.decisions.isEmpty())
    }

    @Test fun zonderActieveKoppelingGeenPoll() {
        DeviceStore(dir).wipe()
        assertFalse(flow.paired())
        try {
            flow.poll()
            fail()
        } catch (e: PairingError.NotPaired) {
            // verwacht
        }
        assertTrue(server.paths.isEmpty())
    }

    @Test fun wireNamenCentraal() {
        assertEquals("sig_req_invalid", ApprovalWire.REASON_SIG_INVALID)
        assertEquals("keyfile_required", ApprovalWire.REASON_KH_MISSING)
        assertEquals(listOf("pub_B", "epk_L", "nonce_L"), listOf(ApprovalWire.PUB_B, ApprovalWire.EPK_L, ApprovalWire.NONCE_L))
        assertEquals("browser_proof_invalid", ApprovalWire.REASON_PROOF_INVALID)
        assertEquals(25, ApprovalWire.WAIT_SECONDS)
    }
}
