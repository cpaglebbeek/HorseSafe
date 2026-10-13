package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyVariant

/** Vaste getallen van de inrichting. */
object Limits {
    /** PIN-lengte en het vast te zetten minimum. */
    const val PIN_LENGTH: Int = 63
    /** Een nieuwe/gezonde sleutel heeft 8 PIN-pogingen. */
    const val FULL_PIN_RETRIES: Int = 8
    /** Bij zoveel of minder pogingen blokkeert de app elke PIN-invoer (F5.1, M8). */
    const val PIN_RETRIES_BLOCK_AT: Int = 3
    /** Hardwaremaximum vingers op een YubiKey Bio (F6). */
    const val MAX_FINGERS: Int = 5
    /** Terugval als de sensor geen maximum voor de naam meldt. */
    const val DEFAULT_FRIENDLY_NAME_BYTES: Int = 15
}

/**
 * Wat te doen als 0x1D (maxPINLength) ontbreekt (open vraag 4, gesloten 13-10-2026 in 0.3.2).
 *
 * 0x1D bestaat pas sinds CTAP 2.2; YubiKey-firmware 5.7 is CTAP 2.1 en meldt het nooit (gemeten op een echte
 * sleutel, en yubikit vult zelf 63 in). In CTAP 2.1 is het maximum vast 63 = onze lengte. setPin(63) is de
 * echte proef en is atomair: weigert de sleutel (bv. Bio MPE met PIV aan), dan PIN_POLICY_MPE_PIV en staat
 * er niets op de sleutel.
 */
enum class MaxPinLengthPolicy {
    /** Standaard: afwezig = CTAP 2.1-maximum 63, oranje melding, setPin is de proef (FIDO en MPE). */
    ASSUME_CTAP21_MAX,
    /** Streng (alleen nog voor tests/terugval): afwezig = STOP. */
    STOP,
}

/** Uitkomst van een beoordeling: regels voor M2/M9/rapport en de eerste harde stop (of null). */
data class Evaluation(val checks: List<CheckResult>, val stop: Stop?) {
    val ok: Boolean get() = stop == null
}

private class CheckList {
    val checks = mutableListOf<CheckResult>()
    var stop: Stop? = null

    fun green(id: String, detail: String) { checks += CheckResult(id, Verdict.GREEN, detail) }
    fun orange(id: String, detail: String) { checks += CheckResult(id, Verdict.ORANGE, detail) }
    fun red(id: String, detail: String, s: Stop) {
        checks += CheckResult(id, Verdict.RED, detail)
        if (stop == null) stop = s
    }
    fun result() = Evaluation(checks.toList(), stop)
}

/**
 * F1 Herkennen: harde eisen per profiel (alleen lezen, geen sleutelverkeer). De volgorde van de regels
 * bepaalt welke stop als eerste getoond wordt: eerst "is dit een toegestane sleutel", dan de spec-eisen.
 */
object DetectionPolicy {

    fun evaluate(facts: KeyFacts, profile: Profile, maxPinPolicy: MaxPinLengthPolicy = MaxPinLengthPolicy.ASSUME_CTAP21_MAX): Evaluation {
        val c = CheckList()

        // AAGUID en klasse.
        if (facts.keyClass == KeyClass.UNKNOWN) {
            c.red("aaguid", "Sleuteltype staat niet op de lijst van toegestane YubiKeys.", Stop.AAGUID_NOT_ALLOWED)
        } else {
            c.green("aaguid", "Sleuteltype toegestaan (${facts.keyClass.jsonName}, variant ${facts.variant.name.lowercase()}).")
            if (facts.keyClass != profile.keyClass) {
                c.red(
                    "klasse",
                    "Aangesloten: ${facts.aaguidDescription ?: facts.keyClass.jsonName} (klasse ${facts.keyClass.jsonName}). Gekozen rol: ${profile.nl} (verwacht klasse ${profile.keyClass.jsonName}).",
                    Stop.CLASS_MISMATCH,
                )
            } else {
                c.green("klasse", "Sleuteltype past bij de rol.")
            }
        }

        // FIDO 2.1 en de vereiste opties.
        if (facts.hasVersion("FIDO_2_1")) c.green("fido_2_1", "FIDO 2.1 aanwezig.")
        else c.red("fido_2_1", "FIDO 2.1 ontbreekt.", Stop.NO_FIDO_2_1)

        when (facts.option("clientPin")) {
            null -> c.red("client_pin", "De sleutel meldt geen PIN-ondersteuning.", Stop.NO_FIDO_2_1)
            true -> c.orange("client_pin", "Er staat al een PIN op de sleutel.")
            false -> c.green("client_pin", "Nog geen PIN op de sleutel.")
        }
        if (facts.option("setMinPINLength") == true) c.green("set_min_pin_length", "Minimale PIN-lengte vast te zetten.")
        else c.red("set_min_pin_length", "setMinPINLength ontbreekt.", Stop.MISSING_SET_MIN_PIN_LENGTH)
        if (facts.option("authnrCfg") == true) c.green("authnr_cfg", "Configuratie (authnrCfg) ondersteund.")
        else c.red("authnr_cfg", "authnrCfg ontbreekt.", Stop.MISSING_AUTHNR_CFG)
        when (facts.option("alwaysUv")) {
            null -> c.red("always_uv", "De optie alwaysUv ontbreekt.", Stop.MISSING_ALWAYS_UV)
            true -> c.green("always_uv", "alwaysUv staat aan.")
            false -> c.orange("always_uv", "alwaysUv staat uit; de app zet hem aan.")
        }
        if (facts.maxRpidsForSetMinPinLength >= 1) c.green("max_rpids", "Minimale PIN-lengte te melden aan ${facts.maxRpidsForSetMinPinLength} site(s).")
        else c.red("max_rpids", "maxRPIDsForSetMinPINLength is kleiner dan 1.", Stop.MAX_RPIDS_TOO_LOW)

        // Firmware per klasse (kritiek 6).
        val fw = facts.firmware
        val min = facts.keyClass.minFirmware
        when {
            fw == null -> c.red("firmware", "Firmwareversie onbekend.", Stop.FIRMWARE_UNKNOWN)
            min != null && fw < min -> c.red(
                "firmware", "Firmware $fw is ouder dan $min (YSA-2024-03).",
                if (facts.keyClass == KeyClass.BIO) Stop.FIRMWARE_TOO_OLD_BIO else Stop.FIRMWARE_TOO_OLD_YK5,
            )
            fw < Firmware.ORANGE_BELOW -> c.orange("firmware", "Firmware $fw is bruikbaar maar ouder dan ${Firmware.ORANGE_BELOW}.")
            else -> c.green("firmware", "Firmware $fw.")
        }

        // maxPINLength (0x1D).
        val max = facts.maxPinLength
        when {
            max != null && max < Limits.PIN_LENGTH -> c.red("max_pin_length", "De sleutel accepteert maximaal $max tekens.", Stop.MAX_PIN_LENGTH_TOO_SHORT)
            max != null -> c.green("max_pin_length", "Maximale PIN-lengte $max.")
            maxPinPolicy == MaxPinLengthPolicy.STOP -> c.red("max_pin_length", "Maximale PIN-lengte onbekend.", Stop.MAX_PIN_LENGTH_UNKNOWN)
            facts.variant == KeyVariant.MPE -> c.orange(
                "max_pin_length",
                "Niet gemeld (CTAP 2.1); volgens CTAP 2.1 is het maximum 63. Multi-protocol: met PIV aan weigert de sleutel 63 tekens bij het zetten van de PIN; er komt dan niets op de sleutel.",
            )
            else -> c.orange("max_pin_length", "Niet gemeld (CTAP 2.1); volgens CTAP 2.1 is het maximum 63. Het zetten van de PIN van 63 tekens is de proef.")
        }

        // Alleen tonen (geen stop).
        when (facts.pinComplexity) {
            true -> c.orange("pin_complexity", "De sleutel heeft een complexiteitsbeleid voor PIN's.")
            false -> c.green("pin_complexity", "Geen complexiteitsbeleid.")
            null -> c.orange("pin_complexity", "Complexiteitsbeleid onbekend.")
        }
        if (facts.serialHmac == null) c.orange("serienummer", "Geen serienummer gemeld; een verwisselde sleutel van hetzelfde model is niet te herkennen.")
        else c.green("serienummer", "Serienummer vastgelegd als HMAC.")
        facts.pinRetries?.let { c.green("pin_retries_info", "PIN-pogingen: $it.") }
        facts.uvRetries?.let { c.green("uv_retries_info", "Vingerpogingen: $it.") }
        return c.result()
    }
}

/** Nieuw-sleutelgate (F2.1/F3) en hervat-gate (F2r/F3r). */
object Gates {

    fun newKey(facts: KeyFacts, profile: Profile): Evaluation {
        val c = CheckList()
        if (facts.option("clientPin") == true) c.red("gate_client_pin", "Er staat al een PIN op de sleutel.", Stop.PIN_ALREADY_SET)
        else c.green("gate_client_pin", "Geen PIN op de sleutel.")
        val retries = facts.pinRetries
        if (retries == null || retries < Limits.FULL_PIN_RETRIES) {
            c.red("gate_pin_retries", "PIN-pogingen niet ${Limits.FULL_PIN_RETRIES}; de sleutel is al gebruikt.", Stop.KEY_ALREADY_USED)
        } else c.green("gate_pin_retries", "${Limits.FULL_PIN_RETRIES} PIN-pogingen.")
        if (facts.forcePinChange) c.red("gate_force_pin_change", "De sleutel eist een PIN-wijziging.", Stop.FORCE_PIN_CHANGE)
        else c.green("gate_force_pin_change", "Geen PIN-wijziging geëist.")
        // Review-bevinding: een YubiKey 5 zonder PIN met alwaysUv aan wijkt af van de fabrieksstand
        // (iemand heeft hem al ingesteld) en makeCredential zonder token zou daarna toch weigeren.
        if (profile.keyClass == KeyClass.YUBIKEY5) {
            if (facts.option("alwaysUv") == true && facts.option("clientPin") != true) {
                c.red("gate_always_uv_preset", "alwaysUv staat al aan zonder PIN; de sleutel is al eerder ingesteld.", Stop.YK5_ALWAYS_UV_PRESET)
            } else c.green("gate_always_uv_preset", "alwaysUv staat in de fabrieksstand.")
        }
        bioRules(facts, profile, c, newKey = true)
        return c.result()
    }

    private fun bioRules(facts: KeyFacts, profile: Profile, c: CheckList, newKey: Boolean) {
        if (profile.keyClass != KeyClass.BIO) return
        val be = facts.option("bioEnroll")
        when {
            profile == Profile.RECOVERY_BIO && be != false ->
                c.red("gate_bio_enroll", "Vingers op de noodsleutel-Bio aanwezig of niet vast te stellen.", Stop.RECOVERY_BIO_HAS_FINGER)
            be == null -> c.red("gate_bio_enroll", "De sleutel meldt geen vingerinschrijving.", Stop.CLASS_MISMATCH)
            be && newKey -> c.red("gate_bio_enroll", "Er staan al vingers op de sleutel.", Stop.BIO_ALREADY_ENROLLED)
            else -> c.green("gate_bio_enroll", if (be) "Vingers aanwezig." else "Nog geen vingers.")
        }
    }

    /** Wat er volgens getInfo nog ontbreekt (vingers worden pas na de PIN-invoer geteld). */
    fun pendingFromFacts(facts: KeyFacts, profile: Profile): Set<Written> {
        val p = mutableSetOf<Written>()
        if (!(facts.rawPresent.minPinLength0x0D && facts.minPinLength >= Limits.PIN_LENGTH)) p += Written.MIN_PIN_LENGTH_63
        if (facts.option("alwaysUv") != true) p += Written.ALWAYS_UV
        if (profile == Profile.BIO_MAIN && facts.option("bioEnroll") != true) p += Written.FINGERPRINTS
        return p
    }

    /**
     * Hervatten mag alleen als clientPin == true en er nog iets ontbreekt (kritiek 2). Resident == 0
     * wordt na de PIN-invoer gecontroleerd. Bij een hoofdsleutel met vingers maar verder compleet kan het
     * aantal vingers (< 2) pas na de PIN blijken; die gaat dan voorlopig door.
     */
    fun resume(facts: KeyFacts, profile: Profile): Pair<Evaluation, Set<Written>> {
        val c = CheckList()
        if (facts.option("clientPin") != true) c.red("resume_client_pin", "Er staat nog geen PIN op de sleutel; kies een nieuwe inrichting.", Stop.RESUME_NOT_ALLOWED)
        else c.green("resume_client_pin", "PIN aanwezig.")
        if (facts.forcePinChange) c.red("resume_force_pin_change", "De sleutel eist een PIN-wijziging.", Stop.FORCE_PIN_CHANGE)
        val retries = facts.pinRetries
        when {
            retries == 0 -> c.red("resume_pin_retries", "De PIN is geblokkeerd.", Stop.PIN_BLOCKED)
            retries == null || retries <= Limits.PIN_RETRIES_BLOCK_AT ->
                c.red("resume_pin_retries", "Nog maar ${retries ?: "onbekend"} PIN-pogingen.", Stop.PIN_RETRIES_LOW)
            else -> c.green("resume_pin_retries", "PIN-pogingen: $retries.")
        }
        bioRules(facts, profile, c, newKey = false)
        val pending = pendingFromFacts(facts, profile)
        val bioMainMaybeFew = profile == Profile.BIO_MAIN && facts.option("bioEnroll") == true
        if (pending.isEmpty() && !bioMainMaybeFew) {
            c.red("resume_pending", "Alles staat al op de sleutel; er valt niets te hervatten.", Stop.RESUME_NOT_ALLOWED)
        }
        return c.result() to pending
    }
}

/**
 * F4a-regels (keuren zonder PIN), ook gebruikt als eindinspectie na het inrichten. [fingerCount] is
 * alleen bekend bij keuren met PIN of na het inrichten.
 */
object KeuringRules {

    fun evaluate(facts: KeyFacts, profile: Profile, fingerCount: Int? = null): Evaluation {
        val c = CheckList()
        if (facts.option("clientPin") == true) c.green("k_client_pin", "PIN aanwezig.")
        else c.red("k_client_pin", "Er staat geen PIN op de sleutel.", Stop.PIN_READBACK_FAILED)
        val r = facts.pinRetries
        when {
            r == Limits.FULL_PIN_RETRIES -> c.green("k_pin_retries", "PIN-pogingen: $r van ${Limits.FULL_PIN_RETRIES}.")
            r == 0 -> c.red("k_pin_retries", "De PIN is geblokkeerd.", Stop.PIN_BLOCKED)
            else -> c.red("k_pin_retries", "Alarm: PIN-pogingen ${r ?: "onbekend"} in plaats van ${Limits.FULL_PIN_RETRIES}.", Stop.PIN_READBACK_FAILED)
        }
        if (facts.rawPresent.minPinLength0x0D && facts.minPinLength == Limits.PIN_LENGTH) c.green("k_min_pin_length", "Minimale PIN-lengte 63.")
        else c.red("k_min_pin_length", "Minimale PIN-lengte is niet 63.", Stop.MIN_PIN_LENGTH_READBACK_FAILED)
        if (!facts.forcePinChange) c.green("k_force_pin_change", "Geen PIN-wijziging geëist.")
        else c.red("k_force_pin_change", "De sleutel eist een PIN-wijziging.", Stop.MIN_PIN_LENGTH_READBACK_FAILED)
        if (facts.option("alwaysUv") == true) c.green("k_always_uv", "alwaysUv staat aan.")
        else c.red("k_always_uv", "alwaysUv staat niet aan.", Stop.ALWAYS_UV_READBACK_FAILED)

        when (profile) {
            Profile.BIO_MAIN -> {
                if (facts.option("bioEnroll") == true) c.green("k_bio_enroll", "Vingers ingeschreven.")
                else c.red("k_bio_enroll", "Geen vingers ingeschreven.", Stop.FINGER_COUNT_INVALID)
                if (facts.uvRetries != null) c.green("k_uv_retries", "Vingerpogingen: ${facts.uvRetries}.")
                else c.orange("k_uv_retries", "Vingerpogingen niet gemeld.")
                if (fingerCount != null) {
                    when {
                        fingerCount in profile.fingers -> c.green("k_fingers", "$fingerCount vingers.")
                        fingerCount == 0 -> c.red("k_fingers", "Geen vingers.", Stop.FINGER_COUNT_INVALID)
                        else -> c.orange("k_fingers", "$fingerCount vingers; advies is ${profile.fingers.first}-${profile.fingers.last}.")
                    }
                }
            }
            Profile.RECOVERY_BIO -> {
                // Kritiek 14: bioEnroll moet aanwezig en false zijn; afwezig = STOP.
                if (facts.option("bioEnroll") == false && facts.option("uv") != true && (fingerCount ?: 0) == 0) {
                    c.green("k_bio_enroll", "Geen vinger op de noodsleutel-Bio.")
                } else c.red("k_bio_enroll", "Vinger op de noodsleutel-Bio aanwezig of niet vast te stellen.", Stop.RECOVERY_BIO_HAS_FINGER)
            }
            Profile.RECOVERY_YK5 -> {
                // Kritiek 10: oranje tot de meting op de testsleutel.
                if (facts.hasVersion("U2F_V2")) c.orange("u2f_after_always_uv", "U2F_V2 staat nog in versions na alwaysUv (afwijkend, vastgelegd).")
                else c.green("u2f_after_always_uv", "U2F_V2 is weg na alwaysUv.")
            }
        }
        return c.result()
    }
}

/** Naam van een vinger: niet leeg, alleen afdrukbare ASCII, lengte in bytes ≤ [maxBytes] (kritiek 15). */
object FingerNames {
    fun valid(name: String, maxBytes: Int): Boolean =
        name.isNotEmpty() && name.all { it.code in 0x20..0x7e } && name.toByteArray(Charsets.US_ASCII).size <= maxBytes &&
            name.trim() == name
}
