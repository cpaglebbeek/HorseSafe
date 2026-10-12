package nl.icthorse.horsesafe.yubikey

import java.security.SecureRandom
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.AttestationEvidence
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission

/**
 * Keurings-makeCredential (`Ctap2Session.makeCredential`):
 * - rp `{id: KEURING_RP_ID, name}`, een willekeurige user-id van 16 bytes;
 * - `pubKeyCredParams [{type: public-key, alg: -7}]`, options `{rk: false}`;
 * - met token: `pinUvAuthParam = protocol.authenticate(token, clientDataHash)` + protocolversie;
 *   zonder token: geen pinUvAuthParam, alleen aanraking (UP), en alleen als er nog geen PIN is en
 *   alwaysUv niet aan staat;
 * - `enterpriseAttestation = null`, geen excludeList, geen extensies.
 *
 * De credential is niet resident; er blijft niets achter op de sleutel. Verificatie van de keten,
 * de vlaggen en de AAGUID gebeurt in `attest/AttestationVerifier`, niet hier.
 */
internal class YubikitAttestOps(
    private val phase: YubikitCtapPhase,
    private val random: SecureRandom = SecureRandom(),
) : AttestOps {

    override suspend fun keuringCredential(token: AuthToken?): AttestationEvidence {
        val rawToken: ByteArray? = token?.let { phase.unwrap(it, Permission.MC) }
        if (rawToken == null) {
            // Contract: zonder token alleen als er geen PIN is en alwaysUv uit staat; anders zou de
            // sleutel PUAT_REQUIRED geven (of, met PIN, stil UV overslaan). Vooraf weigeren.
            phase.call {
                if (phase.option("clientPin") == true || phase.option("alwaysUv") == true) {
                    throw KeyError.PinUvAuthTokenRequired()
                }
            }
        }
        val clientDataHash = ByteArray(32).also(random::nextBytes)
        val userId = ByteArray(16).also(random::nextBytes)
        val rp = mapOf("id" to AttestOps.KEURING_RP_ID, "name" to RP_NAME)
        val user = mapOf("id" to userId, "name" to USER_NAME, "displayName" to USER_NAME)
        val params = listOf(mapOf("type" to "public-key", "alg" to ES256))
        val options = mapOf("rk" to false)

        val state = phase.beginCommand()
        val data = try {
            phase.call {
                val (param, proto) = if (rawToken != null) {
                    phase.protocol.authenticate(rawToken, clientDataHash) to phase.protocol.version
                } else {
                    null to null
                }
                phase.session.makeCredential(
                    clientDataHash, rp, user, params,
                    null, null, options,
                    param, proto,
                    null,
                    state,
                )
            }
        } finally {
            phase.endCommand(state)
        }

        return phase.call {
            val att = data.attestationStatement
            val alg = att["alg"]?.let { it as? Int ?: throw KeyError.Protocol("attStmt-alg") }
            val sig = att["sig"]?.let { it as? ByteArray ?: throw KeyError.Protocol("attStmt-sig") } ?: ByteArray(0)
            val x5c = when (val v = att["x5c"]) {
                null -> emptyList()
                is List<*> -> v.map { it as? ByteArray ?: throw KeyError.Protocol("attStmt-x5c") }
                else -> throw KeyError.Protocol("attStmt-x5c")
            }
            AttestationEvidence(
                fmt = data.format,
                authData = data.authenticatorData,
                alg = alg,
                sig = sig,
                x5c = x5c,
                clientDataHash = clientDataHash,
                rpId = AttestOps.KEURING_RP_ID,
                withToken = rawToken != null,
            )
        }
    }

    companion object {
        const val ES256 = -7
        const val RP_NAME = "HorseSafe keuring"
        const val USER_NAME = "keuring"
    }
}
