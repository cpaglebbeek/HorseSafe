package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission

/**
 * Tokenbeleid (A-19, kritiek 1):
 * - per stap een eigen token met precies één permissie: ACFG voor Config, BE voor de vingers,
 *   CM voor `getMetadata`, MC (met rpId [AttestOps.KEURING_RP_ID]) voor de keuring;
 * - `getPinToken` gaat ALTIJD met een permissie naar subcommand 0x09; is `pinUvAuthToken` niet
 *   `true` in de verse getInfo, dan [KeyError.NotSupported] en dus nooit stil 0x05 (dat zou yubikit
 *   doen: `ClientPin.getPinToken` kiest 0x05 als `isTokenSupported` false is);
 * - een token leeft alleen binnen de [YubikitCtapPhase] waarin het ontstond en wordt bij het sluiten
 *   van die fase gewist.
 */
object Tokens {

    /** De bits moeten gelijk blijven aan yubikit; gecontroleerd in de unittest. */
    internal val YUBIKIT_BITS: Map<Permission, Int> = mapOf(
        Permission.MC to ClientPin.PIN_PERMISSION_MC,
        Permission.CM to ClientPin.PIN_PERMISSION_CM,
        Permission.BE to ClientPin.PIN_PERMISSION_BE,
        Permission.ACFG to ClientPin.PIN_PERMISSION_ACFG,
    )

    /**
     * Controleert een tokenaanvraag vóórdat er iets naar de sleutel gaat.
     * MC alleen met rpId == [AttestOps.KEURING_RP_ID]; de andere permissies zonder rpId.
     * @throws IllegalArgumentException bij misbruik door de aanroeper (programmeerfout, geen sleutelfout).
     */
    fun validateRequest(permission: Permission, rpId: String?) {
        when (permission) {
            Permission.MC -> require(rpId == AttestOps.KEURING_RP_ID) { "MC-token alleen voor de keurings-rpId" }
            Permission.CM, Permission.BE, Permission.ACFG -> require(rpId == null) { "rpId alleen bij MC" }
        }
    }

    /** Permissiebits zoals ze naar de sleutel gaan; nooit null en nooit 0 (kritiek 1). */
    fun bitsFor(permission: Permission): Int {
        val bits = permission.bit
        check(bits != 0 && bits == YUBIKIT_BITS[permission]) { "permissiebits wijken af" }
        return bits
    }

    /** V2 als de sleutel 2 meldt, anders V1; geen van beide → [KeyError.NotSupported]. */
    fun selectProtocol(pinUvAuthProtocols: List<Int>): PinUvAuthProtocol = when {
        PinUvAuthProtocolV2.VERSION in pinUvAuthProtocols -> PinUvAuthProtocolV2()
        PinUvAuthProtocolV1.VERSION in pinUvAuthProtocols -> PinUvAuthProtocolV1()
        else -> throw KeyError.NotSupported("pinUvAuthProtocol")
    }
}

/**
 * [AuthToken] binnen één CTAP-fase. Houdt de tokenbytes zoals yubikit ze teruggaf (geen kopie), zodat
 * [wipe] ook de referentie wist die `Config`/`FingerprintBioEnrollment`/`CredentialManagement`
 * vasthouden. [toString] toont nooit bytes.
 */
internal class PhaseToken(
    override val permission: Permission,
    override val rpId: String?,
    private val bytes: ByteArray,
    internal val owner: Any,
) : AuthToken {
    @Volatile
    private var wiped = false

    override val isWiped: Boolean get() = wiped

    /** De ruwe bytes voor yubikit; alleen binnen de eigen fase. */
    internal fun raw(): ByteArray {
        if (wiped) throw KeyError.TokenInvalid()
        return bytes
    }

    @Synchronized
    override fun wipe() {
        bytes.fill(0)
        wiped = true
    }

    override fun toString(): String =
        "AuthToken(${permission.name}, rpId=${if (rpId == null) "-" else "[gebonden]"}, ${if (wiped) "gewist" else "[verborgen]"})"
}
