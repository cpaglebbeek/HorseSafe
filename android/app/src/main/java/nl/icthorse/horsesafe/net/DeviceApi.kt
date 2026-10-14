package nl.icthorse.horsesafe.net

import java.io.IOException
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

data class DeviceStatus(val deviceId: String, val state: DeviceState, val keys: List<DeviceKey>)

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

    /** `GET /device/v1/status` (D). */
    fun status(deviceId: String, signer: DevKeySigner): DeviceStatus {
        val r = signed("GET", "/device/v1/status", deviceId, signer)
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
        return DeviceStatus(id, state, keys)
    }

    /** `GET /device/v1/keys/{kid}/sealed` (D). */
    fun sealed(deviceId: String, keyId: String, signer: DevKeySigner): SealedCopy {
        requireUuid(keyId)
        val r = signed("GET", "/device/v1/keys/$keyId/sealed", deviceId, signer)
        if (r.status != 200) throw error(r)
        val o = obj(r.body)
        return SealedCopy(str(o, "key_id"), str(o, "vault_id"), str(o, "sealed"))
    }

    private fun signed(method: String, path: String, deviceId: String, signer: DevKeySigner): HttpResponse {
        requireUuid(deviceId)
        val headers = DeviceAuth.headers(deviceId, method, apiPathPrefix + path, ByteArray(0), signer, clockSeconds())
        return call(HttpRequest(method, path, null, headers))
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
    }
}
