package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.fido.CtapException
import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.PinOps
import nl.icthorse.horsesafe.yubikey.api.PinRetries

/**
 * ClientPin-adapter op yubikit 3.0.1 (`ClientPin(session, PinUvAuthProtocolV2|V1)`).
 *
 * Geheimen: de PIN komt alleen als [SecretBuffer] binnen en gaat als `char[]` naar yubikit; deze
 * adapter maakt geen String en houdt geen kopie vast (een eventuele prefix-kopie wordt direct
 * gewist).
 *
 * RESTRISICO B-17 (nagelezen in de yubikit-bron, `ClientPin.java`):
 * - `preparePin(pin, pad)` codeert via `UTF_8.encode(CharBuffer.wrap(pin))`; die tussenbuffer wordt
 *   gewist, maar de teruggegeven `pinBytes` NIET:
 *   - `setPin`: de opgevulde 64 bytes blijven als afval op de heap;
 *   - `changePin`: zowel de nieuwe (64 bytes) als de huidige PIN (ongepad, als invoer van SHA-256);
 *   - `getPinToken`: de huidige PIN (ongepad) als invoer van SHA-256. `pinHash` wordt wel gewist.
 * - Het gedeelde ECDH-geheim (`getSharedSecret().second`) wordt nergens gewist.
 * - yubikit maakt GEEN String van de PIN (geen `new String(pin)`, geen logging van de PIN); de
 *   slf4j-debugregels loggen alleen versleutelde velden, en zonder slf4j-provider is dat een NOP.
 * - `Ctap2Session.clientPin(...)` is package-private, dus een eigen wisbare implementatie kan niet
 *   via de publieke API. Mitigatie: proces beëindigen na elke stap met een PIN (A-12).
 */
internal class YubikitPinOps(private val phase: YubikitCtapPhase) : PinOps {

    override suspend fun pinRetries(): PinRetries = phase.call {
        requireClientPin()
        val r = phase.clientPin().pinRetries
        PinRetries(r.count, r.powerCycleState)
    }

    override suspend fun uvRetries(): Int = phase.call {
        if (!phase.hasOption("uv")) throw KeyError.NotSupported("uv")
        phase.clientPin().uvRetries
    }

    override suspend fun setPin(pin: SecretBuffer) {
        checkPinShape(pin)
        phase.call {
            requireClientPin()
            if (phase.option("clientPin") == true) throw KeyError.OperationDenied()
        }
        try {
            phase.call { pin.withExactChars { chars -> phase.clientPin().setPin(chars) } }
        } finally {
            // A-19: na een schrijfactie altijd vers; ook bij een fout, zodat de flow de werkelijke
            // toestand ziet.
            runCatching { phase.refresh() }
        }
    }

    override suspend fun changePin(current: SecretBuffer, new: SecretBuffer) {
        checkPinShape(current)
        checkPinShape(new)
        phase.call {
            requireClientPin()
            if (phase.option("clientPin") != true) throw KeyError.PinNotSet()
        }
        try {
            withPinInvalidRetries {
                current.withExactChars { cur ->
                    new.withExactChars { nw -> phase.clientPin().changePin(cur, nw) }
                }
            }
        } finally {
            runCatching { phase.refresh() }
        }
    }

    override suspend fun pinToken(pin: SecretBuffer, permission: Permission, rpId: String?): AuthToken {
        Tokens.validateRequest(permission, rpId)
        val bits = Tokens.bitsFor(permission)
        checkPinShape(pin)
        phase.call {
            requireClientPin()
            // Kritiek 1: nooit 0x05 (zonder permissie). yubikit kiest 0x05 als zijn gecachete
            // getInfo geen pinUvAuthToken meldt; daarom hier vooraf op de verse getInfo stoppen.
            if (!phase.tokenSupported()) throw KeyError.NotSupported("pinUvAuthToken")
            if (phase.option("clientPin") != true) throw KeyError.PinNotSet()
        }
        val bytes = withPinInvalidRetries {
            pin.withExactChars { chars -> phase.clientPin().getPinToken(chars, bits, rpId) }
        }
        return phase.register(permission, rpId, bytes)
    }

    override suspend fun uvToken(permission: Permission, rpId: String?): AuthToken {
        Tokens.validateRequest(permission, rpId)
        val bits = Tokens.bitsFor(permission)
        phase.call {
            if (!phase.tokenSupported()) throw KeyError.NotSupported("pinUvAuthToken")
            if (phase.option("uv") != true) throw KeyError.NotSupported("uv")
        }
        val state = phase.beginCommand()
        val bytes = try {
            phase.call {
                try {
                    phase.clientPin().getUvToken(bits, rpId, state)
                } catch (e: CtapException) {
                    if ((e.ctapError.toInt() and 0xFF) == 0x3F) {
                        throw KeyError.UvInvalid(phase.optionalCtap { phase.clientPin().uvRetries })
                    }
                    throw e
                }
            }
        } finally {
            phase.endCommand(state)
        }
        return phase.register(permission, rpId, bytes)
    }

    private fun requireClientPin() {
        if (!phase.hasOption("clientPin")) throw KeyError.NotSupported("clientPin")
        if (phase.info.pinUvAuthProtocols.isEmpty()) throw KeyError.NotSupported("pinUvAuthProtocol")
    }

    /** PIN_INVALID → [KeyError.PinInvalid] met het aantal resterende pogingen (vers gelezen). */
    private fun <T> withPinInvalidRetries(block: () -> T): T = phase.call {
        try {
            block()
        } catch (e: CtapException) {
            if ((e.ctapError.toInt() and 0xFF) == 0x31) {
                throw KeyError.PinInvalid(phase.optionalCtap { phase.clientPin().pinRetries.count })
            }
            throw e
        }
    }

    companion object {
        /**
         * Vorm van een PIN vóór hij naar de sleutel gaat: 4..63 tekens en alleen ASCII, zodat
         * tekens == bytes (63 bytes is het CTAP-maximum). Geen controle tegen een referentie.
         * @throws IllegalArgumentException bij een ongeldige vorm (vaste tekst, zonder inhoud).
         */
        fun checkPinShape(pin: SecretBuffer) {
            require(!pin.isWiped) { "PIN-buffer is gewist" }
            val n = pin.length
            require(n in 4..SecretBuffer.PIN_LENGTH) { "PIN-lengte buiten 4..63" }
            var ascii = true
            for (i in 0 until n) if (pin[i].code !in 0x21..0x7E) ascii = false
            require(ascii) { "PIN bevat tekens buiten ASCII" }
        }
    }
}

/**
 * Leent precies [SecretBuffer.length] tekens. Is de geleende array langer (buffer niet vol), dan
 * een tijdelijke kopie die na [block] direct wordt gewist.
 */
internal fun <T> SecretBuffer.withExactChars(block: (CharArray) -> T): T = useChars { arr ->
    val n = length
    if (arr.size == n) {
        block(arr)
    } else {
        val tmp = arr.copyOf(n)
        try {
            block(tmp)
        } finally {
            tmp.fill('\u0000')
        }
    }
}
