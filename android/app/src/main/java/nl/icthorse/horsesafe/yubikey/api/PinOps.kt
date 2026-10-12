package nl.icthorse.horsesafe.yubikey.api

import nl.icthorse.horsesafe.pin.SecretBuffer

/** Retry-teller van de PIN. */
data class PinRetries(val count: Int, val powerCycleRequired: Boolean?)

/**
 * ClientPin-adapter. PIN's komen alleen als [SecretBuffer] binnen; de adapter maakt geen String-kopie.
 * PinUvAuthProtocol V2 als de sleutel 2 meldt, anders V1.
 */
interface PinOps {
    suspend fun pinRetries(): PinRetries

    /** Alleen zinvol op een sleutel met ingebouwde UV (Bio). */
    suspend fun uvRetries(): Int

    /** F2.4/F3: eerste PIN zetten. Daarna verplicht verse read (`clientPin == true`, retries == 8). */
    suspend fun setPin(pin: SecretBuffer)

    /** F5: PIN wijzigen. Nooit gecombineerd met Config-aanroepen. */
    suspend fun changePin(current: SecretBuffer, new: SecretBuffer)

    /**
     * Token via PIN, ALTIJD met precies één permissie (kritiek 1: nooit `permissions == null` naar
     * subcommand 0x09). Controleert vooraf `ClientPin.isTokenSupported` en valt nooit stil terug op 0x05;
     * anders [KeyError.NotSupported]. [rpId] verplicht bij [Permission.MC].
     * F7(b) oefencontrole = `pinToken(pin, Permission.CM)` en daarna direct wissen.
     */
    suspend fun pinToken(pin: SecretBuffer, permission: Permission, rpId: String? = null): AuthToken

    /** Token via ingebouwde UV (vinger), bv. de testaanraking `uvToken(MC, AttestOps.KEURING_RP_ID)`. */
    suspend fun uvToken(permission: Permission, rpId: String? = null): AuthToken
}
