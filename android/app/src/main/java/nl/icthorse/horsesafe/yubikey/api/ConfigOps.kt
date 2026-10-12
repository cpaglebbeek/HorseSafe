package nl.icthorse.horsesafe.yubikey.api

/**
 * authenticatorConfig-adapter. Bevat precies twee schrijfacties en wordt ALLEEN door de inricht-flows
 * (F2/F3 en "inrichting hervatten") aangeroepen; F5/F6 nooit (A-18). Geen enableEnterpriseAttestation,
 * geen vendorPrototype.
 *
 * Dit bestand is de enige plek in de app-code waar de rpId-string staat (bronbeleid A-18; gelijk aan
 * backend/config.py `webauthn_rp_id`).
 */
interface ConfigOps {
    /**
     * `setMinPinLength(63, listOf(MIN_PIN_RP_ID), forceChangePin = false)` met een [Permission.ACFG]-token.
     * Onomkeerbaar zonder reset. De flow leest daarna vers terug (`minPinLength == 63`, 0x0D aanwezig,
     * `forcePinChange == false`).
     */
    suspend fun setMinPinLength63(token: AuthToken)

    /**
     * Verse read van `alwaysUv`; togglet alleen bij exact `false`, leest daarna opnieuw vers terug.
     * Optie afwezig → [KeyError.NotSupported]. Nooit toggelen bij `true`.
     */
    suspend fun toggleAlwaysUvIfFalse(token: AuthToken): AlwaysUvOutcome

    companion object {
        const val MIN_PIN_LENGTH: Int = 63
        const val MIN_PIN_RP_ID: String = "icthorsecloud.nl"
    }
}

enum class AlwaysUvOutcome {
    /** Stond al aan; niets gedaan. */
    ALREADY_ON,
    /** Stond uit; één keer getoggeld en teruggelezen als aan. */
    TURNED_ON,
}
