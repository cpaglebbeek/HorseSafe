package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.yubikey.api.KeyClass

/** Moment van de attestation-keuring ten opzichte van setPin. */
enum class AttestTiming { BEFORE_SET_PIN, AFTER_SET_PIN }

/**
 * Wat er ingericht wordt. [fingers] = toegestaan aantal vingers na inrichting.
 */
enum class Profile(val nl: String, val keyClass: KeyClass, val fingers: IntRange) {
    /** Hoofdsleutel: YubiKey Bio via USB-C, 2-3 vingers (F2). */
    BIO_MAIN("Hoofdsleutel (YubiKey Bio)", KeyClass.BIO, 2..3),
    /** Noodsleutel: YubiKey 5 NFC, geen vinger, U2F-controle (F3). */
    RECOVERY_YK5("Noodsleutel (YubiKey 5)", KeyClass.YUBIKEY5, 0..0),
    /** Noodsleutel op een Bio zonder vinger (F3); `bioEnroll` moet aanwezig en false zijn (kritiek 14). */
    RECOVERY_BIO("Noodsleutel (YubiKey Bio zonder vinger)", KeyClass.BIO, 0..0);

    /**
     * Vastgestelde volgorde: YubiKey 5 altijd vóór setPin; Bio vóór setPin alleen als alwaysUv=false,
     * anders direct na setPin en vóór setMinPinLength(63).
     */
    fun attestTiming(alwaysUv: Boolean): AttestTiming = when (keyClass) {
        KeyClass.YUBIKEY5 -> AttestTiming.BEFORE_SET_PIN
        else -> if (alwaysUv) AttestTiming.AFTER_SET_PIN else AttestTiming.BEFORE_SET_PIN
    }
}

/** Nieuwe sleutel inrichten, of een gedeeltelijk ingerichte sleutel afmaken (kritiek 2, F2r/F3r). */
enum class SetupMode {
    NEW,
    /** Alleen als clientPin == true, resident == 0 en (minimum < 63 of alwaysUv false of, bij BIO_MAIN, 0 vingers). PIN via M8 van papier. */
    RESUME,
}
