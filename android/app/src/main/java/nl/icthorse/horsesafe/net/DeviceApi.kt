package nl.icthorse.horsesafe.net

import java.io.IOException
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.report.ReportSchemaException
import nl.icthorse.horsesafe.report.StrictJson

/**
 * Fout van de device-API. [status] = HTTP-status (0 = geen verbinding of onleesbaar antwoord),
 * [code] = `detail.error` van de server (bv. `pairing_not_found`, `attestation_invalid`) of null,
 * [serverDateMillis] = de `Date`-header van het foutantwoord (klokwaarschuwing bij 401) of null.
 */
class ApiException(
    val status: Int,
    val code: String?,
    val reason: String? = null,
    val serverDateMillis: Long? = null,
) : Exception("api $status ${code ?: ""}")

/** Claim-request (§13.1/§13.5). Alle waarden zijn de strings die ook in het transcript staan. */
class ClaimRequest(
    val pkC: String,
    val kDevPub: String,
    val kBiosigPub: String,
    val kDevChain: List<String>,
    val kBiosigChain: List<String>,
    val label: String,
    val model: String,
    val appVersion: String,
    val macSrv: String,
    val macWeb: String,
    val sigBiosig: String,
) {
    /**
     * JSON van het claim-request. Veldnamen uit §13.1/§13.5; de namen van de twee ketens (`k_dev_chain`,
     * `k_biosig_chain`) staan niet letterlijk in §13 en zijn gelijk aan `PairingClaim` in
     * `backend/models/device.py` (zie android/README.md, open punten).
     */
    fun toJson(): String = StrictJson.write(
        linkedMapOf(
            "pk_c" to pkC,
            "k_dev_pub" to kDevPub,
            "k_biosig_pub" to kBiosigPub,
            "k_dev_chain" to kDevChain,
            "k_biosig_chain" to kBiosigChain,
            "label" to label,
            "model" to model,
            "app_version" to appVersion,
            "mac_srv" to macSrv,
            "mac_web" to macWeb,
            "sig_biosig" to sigBiosig,
        ),
    )

    override fun toString(): String = "ClaimRequest(label=$label, model=$model)"
}

data class ClaimResponse(val deviceId: String, val sas: String)

data class DeviceKey(val keyId: String, val vaultId: String, val label: String)

enum class DeviceState(val wire: String) { PENDING("pending"), ACTIVE("active"), REVOKED("revoked") }

/**
 * [approvals] = openstaande ontgrendelverzoeken (§14.6, alleen `pending`); leeg bij een server zonder Montgomery.
 */
data class DeviceStatus(
    val deviceId: String,
    val state: DeviceState,
    val keys: List<DeviceKey>,
    val approvals: List<PendingApproval> = emptyList(),
)

/** Eén openstaand verzoek uit de status (§14.6). */
data class PendingApproval(val approvalId: String, val vaultId: String)

/** De vertrouwde browser zoals de server hem bij het verzoek levert (§14.5 stap 4). Geen geheim. */
data class TrustedBrowser(val browserId: String, val pubB: String, val label: String, val proof: String)

/**
 * Detail van een ontgrendelverzoek (`GET /device/v1/approvals/{id}`, §14.5 stap 4). Alleen vorm gecontroleerd;
 * de handtekening (sig_req) en het koppelbewijs (proof) controleert de app zelf (`crypto/TrustV1`).
 * [ip], [ua], [requestedAt], [vaultName] en [expiresAt] zijn alleen voor de kaart (niet ondertekend, mogen ontbreken).
 */
data class ApprovalRequest(
    val approvalId: String,
    val vaultId: String,
    val keyId: String,
    val browser: TrustedBrowser,
    val epkL: String,
    val nonceL: String,
    val createdAt: Long,
    val sigReq: String,
    val ip: String?,
    val ua: String?,
    val requestedAt: Long?,
    val vaultName: String? = null,
    val expiresAt: Long? = null,
)

/** Beslissing van de telefoon (`POST /device/v1/approvals/{id}`, §14.5 stap 5). */
sealed class ApprovalDecision {
    /** [resp] = Seal_v2 purpose `relay` naar epk_L. */
    class Approve(val resp: String) : ApprovalDecision() {
        override fun toString() = "Approve([verzegeld])"
    }

    data class Deny(val reason: String? = null) : ApprovalDecision()

    data class DenyRevoke(val reason: String? = null) : ApprovalDecision()
}

/**
 * Veldnamen en vaste waarden van de Montgomery-device-API (§14.5/§14.6) op één plek, zodat ze bij een
 * contractwijziging of afwijkende backend in één keer aan te passen zijn. Gelijk aan de backend van 0.4.0
 * (16-10-2026): `pub_B`, `epk_L` en `nonce_L` met hoofdletter zoals in §14.5; de rest snake_case.
 */
object ApprovalWire {
    const val APPROVALS = "approvals"
    const val APPROVAL_ID = "approval_id"
    const val VAULT_ID = "vault_id"
    const val KEY_ID = "key_id"
    const val BROWSER = "browser"
    const val BROWSER_ID = "browser_id"
    const val PUB_B = "pub_B"
    const val LABEL = "label"
    const val PROOF = "proof"
    const val EPK_L = "epk_L"
    const val NONCE_L = "nonce_L"
    const val CREATED_AT = "created_at"
    const val SIG_REQ = "sig_req"
    const val IP = "ip"
    const val UA = "ua"
    const val REQUESTED_AT = "requested_at"
    const val VAULT_NAME = "vault_name"
    const val EXPIRES_AT = "expires_at"
    const val DECISION = "decision"
    const val RESP = "resp"
    const val REASON = "reason"

    const val DECISION_APPROVE = "approve"
    const val DECISION_DENY = "deny"
    const val DECISION_DENY_REVOKE = "deny_revoke"

    /** Redenen bij een automatische weigering (§14.5/§14.9). */
    const val REASON_SIG_INVALID = "sig_req_invalid"
    const val REASON_PROOF_INVALID = "browser_proof_invalid"
    const val REASON_KH_MISSING = "keyfile_required"

    const val PATH_APPROVALS = "/device/v1/approvals/"

    /** Long-polling van de status (`?wait=25`). */
    const val WAIT_SECONDS = 25
}

data class SealedCopy(val keyId: String, val vaultId: String, val sealed: String)

/**
 * Device-API (HARDWARE_KEYS §13.4) boven een [HttpTransport]. Antwoorden worden strikt gelezen (`StrictJson`)
 * en op vorm gecontroleerd; een onverwacht antwoord geeft [ApiException] met status 0 of de HTTP-status.
 *
 * @param apiPathPrefix het deel van de basis-URL dat in PATH van de device-handtekening staat: `/api`
 *   (de basis-URL eindigt op `/HorseSafe/api`; getekend wordt "pad vanaf /api", §13.6).
 */
class DeviceApi(
    private val transport: HttpTransport,
    private val clockSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
    private val apiPathPrefix: String = "/api",
) {
    /** `POST /devices/pairings/{id}/claim` (publiek, beveiligd met de MAC's). */
    fun claim(pairingId: String, req: ClaimRequest): ClaimResponse {
        requireUuid(pairingId)
        val body = req.toJson().toByteArray(Charsets.UTF_8)
        val r = call(HttpRequest("POST", "/devices/pairings/$pairingId/claim", body, emptyMap()))
        if (r.status != 201) throw error(r)
        val o = obj(r.body)
        val deviceId = str(o, "device_id").also { requireUuidResponse(it) }
        val sas = str(o, "sas")
        if (!SAS.matches(sas)) throw ApiException(r.status, "bad_response")
        return ClaimResponse(deviceId, sas)
    }

    /**
     * `GET /device/v1/status` (D). Met [waitSeconds] > 0 long-polling (`?wait=N`, §14.6); de querystring staat
     * dan ook in het getekende PATH (§13.6).
     */
    fun status(deviceId: String, signer: DevKeySigner, waitSeconds: Int = 0): DeviceStatus {
        require(waitSeconds in 0..ApprovalWire.WAIT_SECONDS) { "wait buiten 0..25" }
        val path = if (waitSeconds > 0) "/device/v1/status?wait=$waitSeconds" else "/device/v1/status"
        val timeout = if (waitSeconds > 0) (waitSeconds + LONG_POLL_MARGIN_S) * 1000 else null
        val r = signed("GET", path, deviceId, signer, readTimeoutMs = timeout)
        if (r.status != 200) throw error(r)
        val o = obj(r.body)
        val id = str(o, "device_id")
        if (id != deviceId) throw ApiException(r.status, "bad_response")
        val stateWire = str(o, "state")
        val state = DeviceState.entries.firstOrNull { it.wire == stateWire } ?: throw ApiException(r.status, "bad_response")
        val rawKeys = o["keys"] as? List<*> ?: throw ApiException(r.status, "bad_response")
        if (rawKeys.size > MAX_KEYS) throw ApiException(r.status, "bad_response")
        val keys = rawKeys.map { k ->
            val m = k as? Map<*, *> ?: throw ApiException(r.status, "bad_response")
            DeviceKey(
                str(m, "key_id").also { requireUuidResponse(it) },
                str(m, "vault_id").also { requireUuidResponse(it) },
                str(m, "label").also { if (it.length > 64) throw ApiException(r.status, "bad_response") },
            )
        }
        val approvals = when (val raw = o[ApprovalWire.APPROVALS]) {
            null -> emptyList()
            is List<*> -> {
                if (raw.size > MAX_APPROVALS) throw ApiException(r.status, "bad_response")
                raw.map { a ->
                    val m = a as? Map<*, *> ?: throw ApiException(r.status, "bad_response")
                    PendingApproval(
                        str(m, ApprovalWire.APPROVAL_ID).also { requireUuidResponse(it) },
                        str(m, ApprovalWire.VAULT_ID).also { requireUuidResponse(it) },
                    )
                }
            }
            else -> throw ApiException(r.status, "bad_response")
        }
        return DeviceStatus(id, state, keys, approvals)
    }

    /** `GET /device/v1/approvals/{id}` (D, §14.5 stap 4). Strikte vormcontrole; 404 = niet (meer) open. */
    fun approval(deviceId: String, approvalId: String, signer: DevKeySigner): ApprovalRequest {
        requireUuid(approvalId)
        val r = signed("GET", ApprovalWire.PATH_APPROVALS + approvalId, deviceId, signer)
        if (r.status != 200) throw error(r)
        val o = obj(r.body)
        val bad = { ApiException(r.status, "bad_response") }
        val b = o[ApprovalWire.BROWSER] as? Map<*, *> ?: throw bad()
        val browser = TrustedBrowser(
            browserId = str(b, ApprovalWire.BROWSER_ID).also { requireUuidResponse(it) },
            pubB = str(b, ApprovalWire.PUB_B).also { if (it.length > MAX_PUB_B || !b64uOk(it, null)) throw bad() },
            label = str(b, ApprovalWire.LABEL).also { if (it.isEmpty() || it.codePointCount(0, it.length) > MAX_LABEL) throw bad() },
            proof = str(b, ApprovalWire.PROOF).also { if (!b64uOk(it, 32)) throw bad() },
        )
        val createdAt = o[ApprovalWire.CREATED_AT] as? Long ?: throw bad()
        if (createdAt <= 0) throw bad()
        // approval_id in het antwoord (als de server het meestuurt) moet gelijk zijn aan het pad.
        if (o.containsKey(ApprovalWire.APPROVAL_ID) && o[ApprovalWire.APPROVAL_ID] != approvalId) throw bad()
        fun optLong(k: String): Long? = when (val t = o[k]) {
            null -> null
            is Long -> t
            else -> throw bad()
        }
        return ApprovalRequest(
            approvalId = approvalId,
            vaultId = str(o, ApprovalWire.VAULT_ID).also { requireUuidResponse(it) },
            keyId = str(o, ApprovalWire.KEY_ID).also { requireUuidResponse(it) },
            browser = browser,
            epkL = str(o, ApprovalWire.EPK_L).also { if (!b64uOk(it, 32)) throw bad() },
            nonceL = str(o, ApprovalWire.NONCE_L).also { if (!b64uOk(it, 32)) throw bad() },
            createdAt = createdAt,
            sigReq = str(o, ApprovalWire.SIG_REQ).also { if (!b64uOk(it, 64)) throw bad() },
            ip = optStr(o, ApprovalWire.IP, MAX_IP),
            ua = optStr(o, ApprovalWire.UA, MAX_UA),
            requestedAt = optLong(ApprovalWire.REQUESTED_AT),
            vaultName = optStr(o, ApprovalWire.VAULT_NAME, MAX_VAULT_NAME),
            expiresAt = optLong(ApprovalWire.EXPIRES_AT),
        )
    }

    /**
     * `POST /device/v1/approvals/{id}` (D, §14.5 stap 5). Succes = 200 `{approval_id, status}` of 204 (het antwoord
     * wordt niet gebruikt);
     * 409 `approval_not_pending` = al beslist of verlopen.
     */
    fun decide(deviceId: String, approvalId: String, decision: ApprovalDecision, signer: DevKeySigner) {
        requireUuid(approvalId)
        val body = linkedMapOf<String, Any?>()
        when (decision) {
            is ApprovalDecision.Approve -> {
                body[ApprovalWire.DECISION] = ApprovalWire.DECISION_APPROVE
                body[ApprovalWire.RESP] = decision.resp
            }
            is ApprovalDecision.Deny -> {
                body[ApprovalWire.DECISION] = ApprovalWire.DECISION_DENY
                decision.reason?.let { body[ApprovalWire.REASON] = it }
            }
            is ApprovalDecision.DenyRevoke -> {
                body[ApprovalWire.DECISION] = ApprovalWire.DECISION_DENY_REVOKE
                decision.reason?.let { body[ApprovalWire.REASON] = it }
            }
        }
        val bytes = StrictJson.write(body).toByteArray(Charsets.UTF_8)
        val r = signed("POST", ApprovalWire.PATH_APPROVALS + approvalId, deviceId, signer, bytes)
        if (r.status != 200 && r.status != 204) throw error(r)
    }

    /** `GET /device/v1/keys/{kid}/sealed` (D). */
    fun sealed(deviceId: String, keyId: String, signer: DevKeySigner): SealedCopy {
        requireUuid(keyId)
        val r = signed("GET", "/device/v1/keys/$keyId/sealed", deviceId, signer)
        if (r.status != 200) throw error(r)
        val o = obj(r.body)
        return SealedCopy(str(o, "key_id"), str(o, "vault_id"), str(o, "sealed"))
    }

    private fun signed(
        method: String,
        path: String,
        deviceId: String,
        signer: DevKeySigner,
        body: ByteArray? = null,
        readTimeoutMs: Int? = null,
    ): HttpResponse {
        requireUuid(deviceId)
        val headers = DeviceAuth.headers(deviceId, method, apiPathPrefix + path, body ?: ByteArray(0), signer, clockSeconds())
        return call(HttpRequest(method, path, body, headers, readTimeoutMs))
    }

    /** Strikte b64u; [len] = verwachte lengte na decoderen (null = vrij). */
    private fun b64uOk(s: String, len: Int?): Boolean = try {
        val b = B64u.decode(s)
        len == null || b.size == len
    } catch (e: IllegalArgumentException) {
        false
    }

    /** Optionele string (afwezig of null → null); te lang of geen string → bad_response. */
    private fun optStr(o: Map<*, *>, k: String, max: Int): String? = when (val v = o[k]) {
        null -> null
        is String -> v.takeIf { it.length <= max } ?: throw ApiException(0, "bad_response")
        else -> throw ApiException(0, "bad_response")
    }

    private fun call(req: HttpRequest): HttpResponse = try {
        transport.execute(req)
    } catch (e: IOException) {
        throw ApiException(0, "network")
    }

    private fun error(r: HttpResponse): ApiException {
        val o = try {
            StrictJson.parse(r.body) as? Map<*, *>
        } catch (e: ReportSchemaException) {
            null
        }
        val detail = o?.get("detail") as? Map<*, *>
        val code = (detail?.get("error") as? String)?.takeIf { CODE.matches(it) }
        val reason = (detail?.get("reason") as? String)?.takeIf { CODE.matches(it) }
        return ApiException(r.status, code, reason, r.dateMillis)
    }

    private fun obj(text: String): Map<*, *> = try {
        StrictJson.parse(text) as? Map<*, *>
    } catch (e: ReportSchemaException) {
        null
    } ?: throw ApiException(0, "bad_response")

    private fun str(o: Map<*, *>, k: String): String = o[k] as? String ?: throw ApiException(0, "bad_response")

    private fun requireUuid(s: String) = require(UUID.matches(s)) { "geen UUID" }

    private fun requireUuidResponse(s: String) {
        if (!UUID.matches(s)) throw ApiException(0, "bad_response")
    }

    companion object {
        val UUID = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        private val SAS = Regex("^[0-9]{6}$")
        private val CODE = Regex("^[a-z0-9_]{1,64}$")
        private const val MAX_KEYS = 50
        private const val MAX_APPROVALS = 20
        private const val MAX_PUB_B = 256
        private const val MAX_LABEL = 64
        private const val MAX_IP = 64
        private const val MAX_UA = 512
        private const val MAX_VAULT_NAME = 256
        private const val LONG_POLL_MARGIN_S = 10
    }
}
