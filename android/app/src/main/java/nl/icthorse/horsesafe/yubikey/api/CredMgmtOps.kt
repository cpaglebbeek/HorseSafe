package nl.icthorse.horsesafe.yubikey.api

/** `CredentialManagement.getMetadata()`; in UI en rapport "resident credentials". */
data class CredMetadata(val existingResidentCredentials: Int, val maxPossibleRemainingResidentCredentials: Int)

/** Alleen lezen: geen enumerate, geen deleteCredential (A-18). Vraagt een [Permission.CM]-token. */
interface CredMgmtOps {
    suspend fun metadata(token: AuthToken): CredMetadata
}
