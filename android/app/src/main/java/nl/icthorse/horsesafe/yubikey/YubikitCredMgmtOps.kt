package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.fido.ctap.CredentialManagement
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.CredMetadata
import nl.icthorse.horsesafe.yubikey.api.CredMgmtOps
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission

/**
 * Alleen `CredentialManagement.getMetadata()` met een [Permission.CM]-token. Geen enumerate en geen
 * deleteCredential (A-18).
 */
internal class YubikitCredMgmtOps(private val phase: YubikitCtapPhase) : CredMgmtOps {
    override suspend fun metadata(token: AuthToken): CredMetadata {
        val raw = phase.unwrap(token, Permission.CM)
        return phase.call {
            if (!CredentialManagement.isSupported(phase.info)) throw KeyError.NotSupported("credMgmt")
            val m = CredentialManagement(phase.session, phase.protocol, raw).metadata
            CredMetadata(m.existingResidentCredentialsCount, m.maxPossibleRemainingResidentCredentialsCount)
        }
    }
}
