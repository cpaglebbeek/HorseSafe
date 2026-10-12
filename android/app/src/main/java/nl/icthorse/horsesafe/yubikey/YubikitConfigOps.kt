package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.fido.ctap.Config
import nl.icthorse.horsesafe.yubikey.api.AlwaysUvOutcome
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.ConfigOps
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission

/**
 * authenticatorConfig (yubikit `Config(session, protocol, token)`), alleen de twee toegestane
 * schrijfacties. Nooit `enableEnterpriseAttestation` of `vendorPrototype` (A-18).
 * De rpId komt uitsluitend uit [ConfigOps.MIN_PIN_RP_ID] (bronbeleid).
 */
internal class YubikitConfigOps(private val phase: YubikitCtapPhase) : ConfigOps {

    override suspend fun setMinPinLength63(token: AuthToken) {
        val raw = phase.unwrap(token, Permission.ACFG)
        phase.call {
            if (phase.option("authnrCfg") != true) throw KeyError.NotSupported("authnrCfg")
            if (phase.option("setMinPINLength") != true) throw KeyError.NotSupported("setMinPINLength")
            if (phase.info.maxRpidsForSetMinPinLength < 1) throw KeyError.NotSupported("maxRPIDsForSetMinPINLength")
        }
        try {
            phase.call {
                Config(phase.session, phase.protocol, raw).setMinPinLength(
                    ConfigOps.MIN_PIN_LENGTH,
                    listOf(ConfigOps.MIN_PIN_RP_ID),
                    false,
                )
            }
        } finally {
            // A-19: de flow leest vers terug (minPinLength == 63, 0x0D aanwezig, forcePinChange false).
            runCatching { phase.refresh() }
        }
    }

    override suspend fun toggleAlwaysUvIfFalse(token: AuthToken): AlwaysUvOutcome {
        val raw = phase.unwrap(token, Permission.ACFG)
        phase.call {
            if (phase.option("authnrCfg") != true) throw KeyError.NotSupported("authnrCfg")
        }
        // Verse read vóór de beslissing: alleen bij exact false toggelen, nooit bij true of afwezig.
        phase.refresh()
        when (phase.option("alwaysUv")) {
            null -> throw KeyError.NotSupported("alwaysUv")
            true -> return AlwaysUvOutcome.ALREADY_ON
            false -> Unit
        }
        try {
            phase.call { Config(phase.session, phase.protocol, raw).toggleAlwaysUv() }
        } catch (t: Throwable) {
            runCatching { phase.refresh() }
            throw t
        }
        phase.refresh()
        if (phase.option("alwaysUv") != true) throw KeyError.Protocol("alwaysUv-teruglezen")
        return AlwaysUvOutcome.TURNED_ON
    }
}
