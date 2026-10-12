package nl.icthorse.horsesafe.yubikey.api

/** Hoe de sleutel verbonden is. USB = `FidoConnection` (HID), NFC = `SmartCardConnection` (IsoDep). */
enum class Transport { USB, NFC }

/**
 * Klasse van de sleutel volgens `assets/trust/aaguids.json` (veld `class`).
 * [UNKNOWN] = AAGUID niet in de allowlist → altijd STOP.
 *
 * [minFirmware] = harde ondergrens YSA-2024-03 per klasse (kritiek 6): Bio < 5.7.2 en YubiKey 5 < 5.7.0 = STOP.
 */
enum class KeyClass(val jsonName: String?, val minFirmware: Firmware?) {
    BIO("bio", Firmware(5, 7, 2)),
    YUBIKEY5("yubikey5", Firmware(5, 7, 0)),
    UNKNOWN(null, null),
}

/** Editie binnen een klasse. MPE = Multi-protocol Edition (PIV kan de PIN tot 8 tekens beperken). */
enum class KeyVariant { FIDO, MPE, UNKNOWN }

/** Firmwareversie. Vergelijkbaar, zodat beleid als `fw < KeyClass.minFirmware` direct leesbaar is. */
data class Firmware(val major: Int, val minor: Int, val patch: Int) : Comparable<Firmware> {
    override fun compareTo(other: Firmware): Int =
        compareValuesBy(this, other, Firmware::major, Firmware::minor, Firmware::patch)

    override fun toString(): String = "$major.$minor.$patch"

    companion object {
        /** Onder deze versie (maar boven [KeyClass.minFirmware]) is de regel oranje. */
        val ORANGE_BELOW = Firmware(5, 7, 4)
    }
}

/**
 * Waar [KeyFacts.firmware] vandaan komt. Bron van voorkeur is Management (`DeviceInfo.getVersion()`,
 * kritiek: `InfoData.getFirmwareVersion` is package-private); [RAW_GETINFO] = ruwe getInfo-sleutel 0x0E.
 */
enum class FirmwareSource { MANAGEMENT, RAW_GETINFO, NONE }

/** Spiegel van `com.yubico.yubikit.management.FormFactor` (zonder yubikit-type in het contract). */
enum class KeyFormFactor { UNKNOWN, USB_A_KEYCHAIN, USB_A_NANO, USB_C_KEYCHAIN, USB_C_NANO, USB_C_LIGHTNING, USB_A_BIO, USB_C_BIO }

/** Applets die Management kan melden (alleen tonen + instructie, open vraag 7; nooit wijzigen). */
enum class Applet { OTP, U2F, FIDO2, OATH, PIV, OPENPGP, HSMAUTH }

/** AAGUID als canonieke kleine-letter-UUID-string met streepjes, bv. `9dd8d593-2213-438a-97f8-d6b813d51c27`. */
@JvmInline
value class Aaguid(val uuid: String) {
    init {
        require(Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").matches(uuid)) { "geen canonieke AAGUID" }
    }
    override fun toString(): String = uuid
}

/**
 * Welke getInfo-sleutels in de RUWE CBOR-respons aanwezig waren (yubikit vult ontbrekende waarden stil
 * met een standaard; daarom apart gemeten via een eigen getInfo, zie [KeyLink.readRawInfo]).
 */
data class RawPresence(
    /** 0x0C forcePINChange. */
    val forcePinChange0x0C: Boolean,
    /** 0x0D minPINLength. */
    val minPinLength0x0D: Boolean,
    /** 0x0E firmwareVersion. */
    val firmwareVersion0x0E: Boolean,
    /** 0x1D maxPINLength. Afwezig = onbekend → standaard STOP (kritiek 21, open vraag 4). */
    val maxPinLength0x1D: Boolean,
)

/**
 * Alles wat de flows over één sleutel weten, samengesteld door [InspectorOps.inspect] uit drie aparte
 * verbindingen (Management, ruwe getInfo, verse yubikit-getInfo). Bevat GEEN geheimen.
 *
 * Het ruwe serienummer staat bewust niet hier; alleen [serialHmac] (kritiek 8).
 */
data class KeyFacts(
    val transport: Transport,
    val aaguid: Aaguid,
    val keyClass: KeyClass,
    val variant: KeyVariant,
    /** Omschrijving uit aaguids.json, of null als onbekend. */
    val aaguidDescription: String?,
    /** null = niet te bepalen ([firmwareSource] == NONE). */
    val firmware: Firmware?,
    val firmwareSource: FirmwareSource,
    val formFactor: KeyFormFactor,
    /** Hex HMAC-SHA256(app-privé random sleutel, serienummer). null = Management gaf geen serienummer (expliciet melden). */
    val serialHmac: String?,
    /** getInfo 0x01, bv. `FIDO_2_0`, `FIDO_2_1`, `U2F_V2`. */
    val versions: List<String>,
    /** getInfo 0x04 options (bv. `clientPin`, `bioEnroll`, `uv`, `alwaysUv`, `authnrCfg`, `setMinPINLength`, `credMgmt`). Afwezig ≠ false. */
    val options: Map<String, Boolean>,
    val rawPresent: RawPresence,
    /** 0x0D; alleen betekenisvol als [RawPresence.minPinLength0x0D]. */
    val minPinLength: Int,
    /** 0x1D; null = afwezig = onbekend. */
    val maxPinLength: Int?,
    /** 0x0C. */
    val forcePinChange: Boolean,
    /** getPinRetries; null als de sleutel het niet meldt. */
    val pinRetries: Int?,
    /** PinRetries.powerCycleState; true = opnieuw insteken nodig. */
    val pinPowerCycleRequired: Boolean?,
    /** getUvRetries; alleen bij een sleutel met ingebouwde UV (Bio), anders null. */
    val uvRetries: Int?,
    /** getInfo 0x10 maxRPIDsForSetMinPINLength (< 1 = STOP). */
    val maxRpidsForSetMinPinLength: Int,
    /** getInfo 0x06; V2 als 2 aanwezig is, anders V1. */
    val pinUvAuthProtocols: List<Int>,
    /** DeviceInfo.getPinComplexity(); null = onbekend (kritiek 16). */
    val pinComplexity: Boolean?,
    /** Ingeschakelde applets per transport uit Management; null = Management niet beschikbaar. */
    val enabledApplets: Map<Transport, Set<Applet>>?,
) {
    /** Optie lezen zonder afwezig en false te verwarren. */
    fun option(name: String): Boolean? = options[name]

    fun hasVersion(v: String): Boolean = v in versions
}
