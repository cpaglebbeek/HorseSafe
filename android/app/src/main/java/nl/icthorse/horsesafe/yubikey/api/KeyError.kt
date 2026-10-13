package nl.icthorse.horsesafe.yubikey.api

/**
 * Alle fouten van de yubikey-laag. Adapters vertalen yubikit-excepties (CtapException-codes,
 * IOException, time-outs) naar één van deze subklassen en gooien ze vanuit de suspend-functies.
 *
 * Berichten zijn vaste Nederlandse teksten: NOOIT PIN, token, sharedSecret of ruwe respons-bytes
 * in een bericht, en de oorspronkelijke exceptie wordt niet als `cause` meegegeven (A-13).
 */
sealed class KeyError(message: String) : Exception(message) {
    /** Sleutel is losgekoppeld of de verbinding viel weg. */
    class Disconnected : KeyError("De sleutel is losgekoppeld.")
    /** Meer dan één sleutel of een tweede verbinding (F1.1). */
    class MultipleKeys : KeyError("Er is meer dan één sleutel aangesloten.")
    /** Geen aanraking/vinger binnen de tijd (CTAP USER_ACTION_TIMEOUT / KEEPALIVE_CANCEL). */
    class UserActionTimeout : KeyError("Geen aanraking binnen de tijd.")
    /** Gebruiker of app heeft de bewerking afgebroken. */
    class Cancelled : KeyError("Afgebroken.")
    /** PIN_INVALID; [retriesLeft] na de mislukte poging, als bekend. */
    class PinInvalid(val retriesLeft: Int?) : KeyError("De PIN klopt niet.")
    /** PIN_BLOCKED: alle pogingen op. */
    class PinBlocked : KeyError("De PIN is geblokkeerd.")
    /** PIN_AUTH_BLOCKED: drie fouten op rij; sleutel opnieuw insteken. */
    class PinAuthBlocked : KeyError("Te veel fouten; steek de sleutel opnieuw in.")
    /** PIN_POLICY_VIOLATION (bv. MPE met PIV aan, of complexiteitsbeleid). */
    class PinPolicyViolation : KeyError("De sleutel weigert deze PIN.")
    /** PIN_NOT_SET. */
    class PinNotSet : KeyError("Er is nog geen PIN ingesteld.")
    /** PUAT_REQUIRED: bewerking vraagt een token (bv. makeCredential met alwaysUv aan). */
    class PinUvAuthTokenRequired : KeyError("De sleutel vraagt eerst een PIN.")
    /** UV_INVALID: vinger niet herkend. */
    class UvInvalid(val retriesLeft: Int?) : KeyError("Vinger niet herkend.")
    /** UV_BLOCKED: vingerpogingen op. */
    class UvBlocked : KeyError("Vingerherkenning is geblokkeerd.")
    /** Reset: NOT_ALLOWED (0x30) — te laat na insteken of tegen de telefoon houden. */
    class ResetWindowPassed : KeyError("Te laat na het insteken.")
    /** OPERATION_DENIED / NOT_ALLOWED. */
    class OperationDenied : KeyError("De sleutel weigert de bewerking.")
    /** Token heeft de verkeerde permissie of is gewist/verlopen. */
    class TokenInvalid : KeyError("Het token is niet (meer) geldig.")
    /** Functie ontbreekt op de sleutel, bv. tokens (`isTokenSupported` false) of Config. [feature] is een vaste naam. */
    class NotSupported(val feature: String) : KeyError("De sleutel ondersteunt dit niet: $feature.")
    /** Antwoord van de sleutel klopt niet met de spec (onverwachte CBOR, ontbrekend veld). [reason] is een vaste naam. */
    class Protocol(val reason: String) : KeyError("Onverwacht antwoord van de sleutel: $reason.")
    /** Overige CTAP-statuscode. */
    class Ctap(val code: Int) : KeyError("Fout van de sleutel (CTAP 0x%02X).".format(code))
    /** I/O-fout zonder nadere duiding; [kind] = eenvoudige klassenaam van de oorzaak. */
    class Io(val kind: String) : KeyError("Verbindingsfout ($kind).")
}
