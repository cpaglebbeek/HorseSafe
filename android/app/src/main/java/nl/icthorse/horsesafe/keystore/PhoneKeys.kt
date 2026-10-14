package nl.icthorse.horsesafe.keystore

import java.security.Signature
import javax.crypto.Cipher

/** Opslagniveau van een Keystore-sleutel (KeyInfo.securityLevel). */
enum class KeyLevel { STRONGBOX, TEE, SOFTWARE, UNKNOWN }

/**
 * Publieke kant van de koppelsleutels na het aanmaken (§13.1-codering): SPKI-DER en de
 * attestatieketens (DER, leaf eerst). Geen geheim.
 */
class PhoneKeyMaterial(
    val kDevSpki: ByteArray,
    val kBiosigSpki: ByteArray,
    val kDevChain: List<ByteArray>,
    val kBiosigChain: List<ByteArray>,
    val kDevLevel: KeyLevel,
    val kBiosigLevel: KeyLevel,
    val kWrapLevel: KeyLevel,
)

/**
 * De biometrische sleutel is ongeldig geworden (nieuwe of verwijderde vingerafdruk,
 * KeyPermanentlyInvalidatedException) of bestaat niet meer. Gevolg (§13.2): alles lokaal wissen en
 * scherm "Opnieuw koppelen".
 */
class KeysInvalidatedException : Exception("sleutels ongeldig")

/** De Keystore kon de sleutels niet (hardwarematig) maken. */
class KeystoreUnavailableException(val why: String) : Exception(why)

/**
 * Sleutelset in de Keystore. Een nieuwe koppeling maakt haar sleutels in de set die niet in gebruik is
 * ([other]); pas na een geslaagde claim (201) wordt die set de actieve (koppelbestand) en de oude gewist.
 */
enum class KeySlot {
    A, B;

    fun other(): KeySlot = if (this == A) B else A
}

/**
 * Telefoonsleutels K_dev, K_biosig en K_wrap (HARDWARE_KEYS §2, §13.2), per [KeySlot]. Implementatie: [AndroidPhoneKeys].
 *
 * Elke bewerking met K_biosig of K_wrap vraagt een vinger via `biometric/StrongGate` met het object dat
 * deze interface teruggeeft als CryptoObject (timeout 0: per gebruik).
 */
interface PhoneKeys {
    /** Wist eventuele oude sleutels in [slot] en maakt daar drie nieuwe, met [attChallenge] in de attestation (§13.1). De andere set blijft onaangeroerd. */
    fun create(attChallenge: ByteArray, slot: KeySlot): PhoneKeyMaterial

    /** Cipher (AES-256-GCM, ENCRYPT) met K_wrap; pas na de vinger bruikbaar. */
    @Throws(KeysInvalidatedException::class)
    fun wrapCipher(slot: KeySlot): Cipher

    /** Cipher (DECRYPT) met K_wrap en [iv]; pas na de vinger bruikbaar. */
    @Throws(KeysInvalidatedException::class)
    fun unwrapCipher(slot: KeySlot, iv: ByteArray): Cipher

    /** Signature (SHA256withECDSA) met K_biosig; pas na de vinger bruikbaar. */
    @Throws(KeysInvalidatedException::class)
    fun biosigSignature(slot: KeySlot): Signature

    /** Ondertekenen met K_dev (geen vinger; alleen met ontgrendeld toestel). */
    @Throws(KeysInvalidatedException::class)
    fun signDev(slot: KeySlot, message: ByteArray): ByteArray

    /** Bestaan alle drie de sleutels van [slot] nog? */
    fun present(slot: KeySlot): Boolean

    /** Verwijdert de drie sleutels van [slot] (best effort). */
    fun delete(slot: KeySlot)

    /** Verwijdert de sleutels van beide sets (best effort). */
    fun deleteAll()
}
