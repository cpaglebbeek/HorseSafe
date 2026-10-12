package nl.icthorse.horsesafe.yubikey.api

/**
 * Ruwe uitkomst van de keurings-makeCredential, voor `attest/AttestationVerifier`. Bevat alleen data
 * van de wegwerp-credential op [AttestOps.KEURING_RP_ID] (rk=false); niets daarvan is geheim, maar
 * credentialId en publieke sleutel gaan niet in het rapport (A-21).
 */
class AttestationEvidence(
    /** Attestation-format, verwacht `packed`. */
    val fmt: String,
    /** authenticatorData zoals ontvangen. */
    val authData: ByteArray,
    /** attStmt.alg, null als afwezig. */
    val alg: Int?,
    /** attStmt.sig. */
    val sig: ByteArray,
    /** attStmt.x5c (DER, leaf eerst); leeg = self/none-attestation → STOP. */
    val x5c: List<ByteArray>,
    /** De clientDataHash die naar de sleutel ging. */
    val clientDataHash: ByteArray,
    val rpId: String,
    /** true = gemaakt met pinUvAuthParam (UV verwacht), false = alleen aanraking (YK5 vóór setPin). */
    val withToken: Boolean,
) {
    override fun toString(): String = "AttestationEvidence(fmt=$fmt, x5c=${x5c.size}, withToken=$withToken)"
}

/**
 * Keurings-makeCredential: rp `{id: KEURING_RP_ID}`, `pubKeyCredParams [-7]`, options `{rk:false}`,
 * `enterpriseAttestation = null`. Nooit rpId `icthorsecloud.nl` (A-18).
 *
 * Volgorde (vastgesteld): YubiKey 5 vóór setPin; Bio vóór setPin alleen als alwaysUv=false, anders direct
 * na setPin en vóór setMinPinLength.
 */
interface AttestOps {
    /**
     * @param token [Permission.MC]-token gebonden aan [KEURING_RP_ID], of null = alleen aanraking (UP),
     *   toegestaan zolang er geen PIN is en alwaysUv uit staat.
     */
    suspend fun keuringCredential(token: AuthToken?): AttestationEvidence

    companion object {
        const val KEURING_RP_ID: String = "keuring.horsesafe.invalid"
    }
}
