package nl.icthorse.horsesafe.yubikey.api

/**
 * Wissen van het FIDO-deel (CTAP `authenticatorReset`, 0x07). De ENIGE plek in de app die de sleutel
 * kan wissen (0.3.1, akkoord Christian 13-10-2026); alleen [nl.icthorse.horsesafe.flow.ResetFlow] roept
 * dit aan, na bevestiging met de laatste 4 cijfers van het serienummer en 3 s ingedrukt houden.
 *
 * Wist alle FIDO-credentials, de PIN, de vingers, het minimum en alwaysUv. PIV, OATH en OpenPGP blijven.
 * Een YubiKey accepteert dit alleen in de eerste seconden na insteken of tegen de telefoon houden
 * ([KeyError.ResetWindowPassed]) en vraagt een aanraking ([KeyError.UserActionTimeout] als die uitblijft).
 */
interface ResetOps {
    suspend fun wipeFido()
}
