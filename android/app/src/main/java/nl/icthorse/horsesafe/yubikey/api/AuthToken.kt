package nl.icthorse.horsesafe.yubikey.api

/**
 * CTAP 2.1 pinUvAuthToken-permissies die HorseSafe gebruikt. Per stap precies één (A-19).
 * Bits gelijk aan `ClientPin.PIN_PERMISSION_*`.
 */
enum class Permission(val bit: Int) {
    /** makeCredential — alleen voor de keuring op [AttestOps.KEURING_RP_ID]. */
    MC(0x01),
    /** credentialManagement — alleen `getMetadata`. */
    CM(0x04),
    /** bioEnrollment. */
    BE(0x08),
    /** authenticatorConfig. */
    ACFG(0x20),
}

/**
 * Ondoorzichtig pinUvAuthToken, geldig binnen één [CtapPhase] (één verbinding, kritiek 22).
 * Nooit buiten die fase bewaren, nooit loggen; [toString] toont geen bytes.
 * Na [wipe] gooit elk gebruik [KeyError.TokenInvalid].
 */
interface AuthToken : AutoCloseable {
    val permission: Permission
    /** rpId waaraan het token gebonden is (verplicht bij [Permission.MC]), anders null. */
    val rpId: String?
    val isWiped: Boolean

    /** Overschrijft de tokenbytes met nullen. Idempotent. */
    fun wipe()

    override fun close() = wipe()
}
