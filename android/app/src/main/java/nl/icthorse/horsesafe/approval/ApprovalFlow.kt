package nl.icthorse.horsesafe.approval

import java.io.IOException
import java.security.GeneralSecurityException
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.crypto.SealException
import nl.icthorse.horsesafe.crypto.SealV2
import nl.icthorse.horsesafe.crypto.SealedSecret
import nl.icthorse.horsesafe.crypto.TrustException
import nl.icthorse.horsesafe.crypto.TrustV1
import nl.icthorse.horsesafe.crypto.X25519
import nl.icthorse.horsesafe.keystore.KeysInvalidatedException
import nl.icthorse.horsesafe.keystore.KeystoreUnavailableException
import nl.icthorse.horsesafe.keystore.PhoneKeys
import nl.icthorse.horsesafe.net.ApiException
import nl.icthorse.horsesafe.net.ApprovalDecision
import nl.icthorse.horsesafe.net.ApprovalRequest
import nl.icthorse.horsesafe.net.ApprovalWire
import nl.icthorse.horsesafe.net.DevKeySigner
import nl.icthorse.horsesafe.net.DeviceApi
import nl.icthorse.horsesafe.net.DeviceState
import nl.icthorse.horsesafe.net.PendingApproval
import nl.icthorse.horsesafe.pairing.DeviceInfo
import nl.icthorse.horsesafe.pairing.DeviceRecord
import nl.icthorse.horsesafe.pairing.DeviceStore
import nl.icthorse.horsesafe.pairing.Finger
import nl.icthorse.horsesafe.pairing.FingerStep
import nl.icthorse.horsesafe.pairing.LocalState
import nl.icthorse.horsesafe.pairing.PairingError

/** Hoe de kaart het verzoek beoordeelt vóór de vinger. */
enum class CardTrust {
    /** sig_req klopt met pub_B; goedkeuren mogelijk (proof volgt na de vinger). */
    SIGNED,

    /** sig_req klopt niet: automatisch geweigerd met reden `sig_req_invalid`. */
    SIG_INVALID,

    /** Browsernaam voldoet niet aan de tekenregel (§13.5.1): niet goedkeurbaar, alleen weigeren. */
    LABEL_INVALID,

    /** Verzoek ouder dan [ApprovalFlow.MAX_AGE_S] of uit de toekomst: niet goedkeurbaar. */
    EXPIRED,

    /** Geen eigen kopie (key_id/vault_id) voor deze kluis op deze telefoon: niet goedkeurbaar. */
    NO_COPY,
}

/**
 * Wat de goedkeuringskaart toont (§11.3.5, §14.9). Geen geheimen. [browserLabel] komt uit het koppelbewijs en is
 * vóór de vinger nog niet gecontroleerd (alleen de handtekening wel); het bewijs wordt ná de vinger gecontroleerd.
 */
data class ApprovalCard(
    val request: ApprovalRequest,
    val trust: CardTrust,
    /** Kluisnaam: `vault_name` van de server, anders het label van de eigen kopie (uit de status), of null. */
    val vaultLabel: String?,
    /** Automatische weigering is verstuurd (bij [CardTrust.SIG_INVALID]). */
    val autoDenied: Boolean = false,
) {
    val approvalId: String get() = request.approvalId
    val browserLabel: String get() = DeviceInfo.clean(request.browser.label, 64, "(zonder naam)")
    val canApprove: Boolean get() = trust == CardTrust.SIGNED

    /** UA voor de kaart: tekenregel §13.5.1 (stuur-/opmaaktekens, Zl/Zp, losse surrogaten weg), max [UA_MAX] tekens. */
    val displayUa: String get() = DeviceInfo.clean(request.ua, UA_MAX, UNKNOWN)

    /** IP voor de kaart: alleen IPv4/IPv6-tekens (cijfers, a-f, ':' en '.'), anders "onbekend". */
    val displayIp: String get() = request.ip?.takeIf { IP.matches(it) && it.any(Char::isDigit) } ?: UNKNOWN

    companion object {
        const val UA_MAX = 200
        const val UNKNOWN = "onbekend"
        private val IP = Regex("^[0-9A-Fa-f:.]{2,45}$")
    }
}

/** Uitkomst van "Goedkeuren". */
sealed class ApproveOutcome {
    data object Approved : ApproveOutcome()

    /** Na de vinger geweigerd door de app: [reason] = `browser_proof_invalid` of `keyfile_required` (deny verstuurd). */
    data class Rejected(val reason: String) : ApproveOutcome()
}

/** Fouten bij goedkeuren/weigeren die niet onder [PairingError] vallen. */
sealed class ApprovalError : Exception() {
    /** 404/409/410: het verzoek is al beslist, verlopen of ingetrokken. */
    data object Gone : ApprovalError()

    /** De eigen kopie ging niet open (verouderd of verkeerd): niets beslist. */
    data class Unseal(val code: String) : ApprovalError()

    /** epk_L van de browser is onbruikbaar (bv. lage-orde-punt): niets beslist. */
    data object BadBrowserKey : ApprovalError()
}

/**
 * Ontgrendelen met de telefoon, kant van de app (HARDWARE_KEYS §14.5 stap 3-5, §14.9).
 *
 * Volgorde: verzoek ophalen → sig_req controleren (VÓÓR de vinger; fout → `deny` met `sig_req_invalid`) → kaart →
 * "Goedkeuren": eigen `store`-kopie ophalen → vinger (K_wrap, alleen BIOMETRIC_STRONG via `biometric/StrongGate`)
 * → sk_c → kopie openen met AAD (vault_id, key_id) → CK → kh verplicht → proof controleren (timing-safe; fout →
 * `deny` met `browser_proof_invalid`) → resp = Seal_v2 relay naar epk_L → `approve`. sk_c, CK en k_bind worden
 * in `finally` gewist.
 */
class ApprovalFlow(
    private val keys: PhoneKeys,
    private val finger: Finger,
    private val api: DeviceApi,
    private val store: DeviceStore,
    /** Lokaal alles wissen (koppelbestand + sleutels), zoals `PairingFlow.wipeLocal`. */
    private val wipeLocal: () -> Unit,
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
) {
    private fun devSigner(rec: DeviceRecord) = DevKeySigner { msg -> keys.signDev(rec.slot, msg) }

    /** Alleen een actieve koppeling pollt. */
    fun paired(): Boolean = try {
        store.load()?.state == LocalState.ACTIVE
    } catch (e: RuntimeException) {
        false
    }

    /**
     * Eén long-poll (`GET /device/v1/status?wait=25`). Werkt de sleutellijst lokaal bij. Alleen `revoked` (200)
     * wist lokaal; 401/404 → [PairingError.DeviceUnknown]; netwerk/5xx/429 → [PairingError.Api] (aanroeper wacht en
     * probeert opnieuw).
     */
    fun poll(waitSeconds: Int = ApprovalWire.WAIT_SECONDS): List<PendingApproval> {
        val rec = store.load() ?: throw PairingError.NotPaired
        if (rec.state != LocalState.ACTIVE) throw PairingError.NotPaired
        val st = try {
            guard { api.status(rec.deviceId, devSigner(rec), waitSeconds) }
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } catch (e: ApiException) {
            if (e.status == 401 || e.status == 404) throw PairingError.DeviceUnknown(e.status, null)
            throw PairingError.Api(e.status, e.code, e.reason)
        }
        return when (st.state) {
            DeviceState.REVOKED -> {
                wipeLocal()
                throw PairingError.Revoked
            }
            DeviceState.PENDING -> emptyList()
            DeviceState.ACTIVE -> {
                if (st.keys != rec.keys) {
                    try {
                        store.save(rec.with(keys = st.keys))
                    } catch (e: IOException) {
                        // Niet fataal: de oude lijst blijft staan; volgende poll probeert opnieuw.
                    }
                }
                st.approvals
            }
        }
    }

    /**
     * Verzoek ophalen en vóór de vinger beoordelen. Klopt sig_req niet, dan wordt meteen `deny` met reden
     * `sig_req_invalid` verstuurd (best effort) en is de kaart niet goedkeurbaar.
     */
    fun load(pending: PendingApproval): ApprovalCard {
        val rec = store.load() ?: throw PairingError.NotPaired
        val req = try {
            guard { api.approval(rec.deviceId, pending.approvalId, devSigner(rec)) }
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } catch (e: ApiException) {
            throw apiError(e)
        }
        // De status en het detail moeten over dezelfde kluis gaan; anders vertrouwen we het detail niet.
        if (req.vaultId != pending.vaultId) throw PairingError.Api(0, "bad_response", null)
        val own = rec.keys.firstOrNull { it.keyId == req.keyId && it.vaultId == req.vaultId }

        val sigOk = signatureValid(req)
        if (!sigOk) {
            val sent = try {
                decide(rec, req.approvalId, ApprovalDecision.Deny(ApprovalWire.REASON_SIG_INVALID))
                true
            } catch (e: Exception) {
                false
            }
            return ApprovalCard(req, CardTrust.SIG_INVALID, vaultName(req, own?.label), autoDenied = sent)
        }
        val trust = when {
            !labelValid(req.browser.label) -> CardTrust.LABEL_INVALID
            !fresh(req.createdAt) || expired(req.expiresAt) -> CardTrust.EXPIRED
            own == null -> CardTrust.NO_COPY
            else -> CardTrust.SIGNED
        }
        return ApprovalCard(req, trust, vaultName(req, own?.label))
    }

    private fun vaultName(req: ApprovalRequest, ownLabel: String?): String? =
        req.vaultName?.let { DeviceInfo.clean(it, 64, "") }?.takeIf { it.isNotEmpty() } ?: ownLabel

    /** sig_req over req_t met pub_B (§14.2); elke vormfout = ongeldig. */
    fun signatureValid(req: ApprovalRequest): Boolean {
        val sig = try {
            B64u.decode(req.sigReq, TrustV1.SIG_LEN)
        } catch (e: IllegalArgumentException) {
            return false
        }
        val t = try {
            TrustV1.reqT(req.approvalId, req.vaultId, req.browser.browserId, req.epkL, req.nonceL, req.createdAt)
        } catch (e: IllegalArgumentException) {
            return false
        }
        return TrustV1.verifySigReq(req.browser.pubB, t, sig)
    }

    /**
     * "Goedkeuren (vinger)". Alleen bij [CardTrust.SIGNED]; sig_req wordt hier opnieuw gecontroleerd.
     * @throws ApprovalError, PairingError of de vingerfout (annuleren) — in die gevallen is er niets beslist.
     */
    suspend fun approve(card: ApprovalCard): ApproveOutcome {
        require(card.canApprove) { "kaart niet goedkeurbaar" }
        val req = card.request
        if (!signatureValid(req)) throw IllegalStateException("handtekening ongeldig")
        if (!fresh(req.createdAt)) throw ApprovalError.Gone
        val rec = store.load() ?: throw PairingError.NotPaired
        val own = rec.keys.firstOrNull { it.keyId == req.keyId && it.vaultId == req.vaultId } ?: throw PairingError.NotPaired
        val epkL = try {
            B64u.decode(req.epkL, X25519.KEY_LEN)
        } catch (e: IllegalArgumentException) {
            throw ApprovalError.BadBrowserKey
        }

        // Eigen store-kopie (publiek, verzegeld) vóór de vinger ophalen; geopend wordt pas na de vinger.
        val copy = try {
            guard { api.sealed(rec.deviceId, own.keyId, devSigner(rec)) }
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } catch (e: ApiException) {
            if (e.status == 401) throw PairingError.DeviceUnknown(401, null)
            throw PairingError.Api(e.status, e.code, e.reason)
        }
        if (copy.keyId != own.keyId || copy.vaultId != own.vaultId) throw ApprovalError.Unseal("unseal_failed")

        var sk: ByteArray? = null
        var ck: SealedSecret? = null
        val (decision, outcome) = try {
            val c = finger.cipher(guard { keys.unwrapCipher(rec.slot, rec.wrappedIv) }, FingerStep.APPROVE)
            val skc = guard { c.doFinal(rec.wrappedCt) }
            sk = skc
            if (skc.size != X25519.KEY_LEN) throw ApprovalError.Unseal("unseal_failed")
            val opened = try {
                SealV2.open(copy.sealed, skc, SealV2.PURPOSE_STORE, own.vaultId, own.keyId)
            } catch (e: SealException) {
                throw ApprovalError.Unseal(e.code)
            }
            ck = opened
            skc.fill(0)
            val b = req.browser
            val proofOk = try {
                TrustV1.verifyProof(opened, req.vaultId, b.browserId, b.pubB, b.label, b.proof)
            } catch (e: TrustException) {
                null // kh ontbreekt: vertrouwen kan alleen bij een kluis met keyfile (§11.3.7)
            }
            when (proofOk) {
                null -> ApprovalDecision.Deny(ApprovalWire.REASON_KH_MISSING) to ApproveOutcome.Rejected(ApprovalWire.REASON_KH_MISSING)
                false -> ApprovalDecision.Deny(ApprovalWire.REASON_PROOF_INVALID) to ApproveOutcome.Rejected(ApprovalWire.REASON_PROOF_INVALID)
                true -> {
                    val resp = try {
                        TrustV1.sealRelay(epkL, opened, req.vaultId, req.approvalId, req.nonceL)
                    } catch (e: IllegalArgumentException) {
                        throw ApprovalError.BadBrowserKey // bv. epk_L is een lage-orde-punt
                    }
                    ApprovalDecision.Approve(resp) to ApproveOutcome.Approved
                }
            }
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } finally {
            sk?.fill(0)
            ck?.wipe()
        }
        // CK en sk_c zijn hier al gewist; alleen het verzegelde antwoord gaat de deur uit.
        decide(rec, req.approvalId, decision)
        return outcome
    }

    /** "Weigeren" ([revoke] = false) of "Weigeren en browser intrekken" ([revoke] = true). */
    fun deny(card: ApprovalCard, revoke: Boolean) {
        val rec = store.load() ?: throw PairingError.NotPaired
        decide(rec, card.approvalId, if (revoke) ApprovalDecision.DenyRevoke() else ApprovalDecision.Deny())
    }

    private fun decide(rec: DeviceRecord, approvalId: String, d: ApprovalDecision) {
        try {
            guard { api.decide(rec.deviceId, approvalId, d, devSigner(rec)) }
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } catch (e: ApiException) {
            throw apiError(e)
        }
    }

    private fun apiError(e: ApiException): Exception = when {
        e.status == 404 || e.status == 409 || e.status == 410 -> ApprovalError.Gone
        e.status == 401 -> PairingError.DeviceUnknown(401, null)
        else -> PairingError.Api(e.status, e.code, e.reason)
    }

    /**
     * Verzoek niet ouder dan [MAX_AGE_S] en niet meer dan [MAX_FUTURE_S] in de toekomst. De server laat een
     * verzoek na 120 s vervallen en de device-handtekening eist al een klok binnen 60 s (§13.6); deze grens is
     * dus ruim en vangt alleen een oud, opnieuw aangeboden verzoek af.
     */
    fun fresh(createdAt: Long): Boolean {
        val now = clockMillis() / 1000
        val age = now - createdAt
        return age <= MAX_AGE_S && -age <= MAX_FUTURE_S
    }

    /** `expires_at` van de server (niet ondertekend; alleen als extra rem): verstreken → niet meer goedkeurbaar. */
    private fun expired(expiresAt: Long?): Boolean = expiresAt != null && clockMillis() / 1000 > expiresAt

    /** Tekenregel §13.5.1 voor de browsernaam: 1-64 tekens, geen stuur-, opmaak- of losse surrogaattekens. */
    private fun labelValid(label: String): Boolean {
        if (label.isEmpty() || label.codePointCount(0, label.length) > 64) return false
        return label.codePoints().allMatch { DeviceInfo.allowed(it) }
    }

    private inline fun <T> guard(block: () -> T): T = try {
        block()
    } catch (e: KeystoreUnavailableException) {
        throw PairingError.Keystore(e.why)
    } catch (e: GeneralSecurityException) {
        throw PairingError.Keystore("bewerking geweigerd")
    }

    companion object {
        const val MAX_AGE_S = 300L
        const val MAX_FUTURE_S = 120L
    }
}
