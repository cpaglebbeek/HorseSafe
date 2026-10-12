package nl.icthorse.horsesafe.ui

import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.Written
import nl.icthorse.horsesafe.yubikey.api.KeyFormFactor

/**
 * Nederlandse teksten van de schermen. Bewust zonder de domeinnaam van de server (bronbeleid A-18,
 * kritiek 18): die staat alleen in `yubikey/api/ConfigOps.kt`.
 */
object Texts {
    const val APP_TITLE = "HorseSafe — YubiKey inrichten en keuren"

    val checklist: List<String> = listOf(
        "Vliegtuigmodus staat aan.",
        "Geen DeX, Link to Windows, Smart View of andere schermkoppeling.",
        "Ontwikkelaarsopties en USB-foutopsporing staan uit.",
        "Auto Blocker staat weer aan na de installatie.",
        "Niemand kijkt mee en er hangt geen camera boven het scherm.",
        "Pigmentpen en het voorgedrukte formulier (9 × (7 + 1) vakjes) liggen klaar.",
    )

    const val CONNECT_USB = "Steek één YubiKey direct in de USB-C-poort, zonder hub of dock."
    const val CONNECT_OTG = "De YubiKey 5 NFC is een USB-A-sleutel: gebruik één OTG-adapter van USB-A naar USB-C."
    const val CONNECT_DIALOG = "Vraagt Android om toestemming voor de sleutel: tik op Toestaan, maar vink \"altijd openen\" NIET aan."
    const val CONNECT_NFC = "Bij keuren zonder PIN mag je de noodsleutel ook tegen de achterkant van de telefoon houden (NFC)."

    const val REVEAL_HELP = "Houd een kaart ingedrukt om de groep te zien. Schrijf de 7 tekens en het omkaderde controleteken over in het vakje met hetzelfde nummer. Laat los en de kaart wordt weer leeg."
    const val REVEAL_BLOCKED = "Tonen is geblokkeerd: het venster is niet zichtbaar, wordt opgenomen of de omgeving is niet veilig."

    const val COPY_HELP = "Controleer je papier: 9 genummerde groepen van 7 tekens, elk met een controleteken. Twijfel je over een teken? Ga terug en kijk nog eens."
    const val COPY_CONFIRM = "Ik heb alle 9 groepen met hun controleteken op papier gezet en gecontroleerd."

    const val RETYPE_HELP = "Typ de PIN van het papier over, groep voor groep, zonder controletekens. Na elke groep zie je alleen of hij klopt."
    const val PAPER_HELP = "Typ per groep de 7 tekens en daarna het controleteken van het papier. Een fout controleteken kost geen poging op de sleutel."

    const val IRREVERSIBLE_TITLE = "Onomkeerbaar"
    const val IRREVERSIBLE_TEXT = "De minimale PIN-lengte 63 kan alleen nog omhoog en is alleen terug te draaien met een reset die alles op de sleutel wist."
    const val IRREVERSIBLE_TICK = "Ik begrijp dat dit niet terug kan."
    const val IRREVERSIBLE_BUTTON = "Ik begrijp het, vastzetten"

    const val TOUCH = "Raak de sleutel aan als hij knippert, of leg je vinger op de sensor."

    const val QUIT_INFO = "\"Afsluiten\" wist de PIN uit het geheugen en beëindigt de app."
    /**
     * Kritiek 7, variant 2: de app kan tussen twee sessies (twee processen) niet controleren dat de PIN
     * van de noodsleutel een andere is dan die van de hoofdsleutel. Daarom een vaste papierregel en
     * restrisicomelding (F3).
     */
    const val DIFFERENT_PINS = "De PIN van de noodsleutel is een andere dan die van de hoofdsleutel. De app kan dat tussen twee sessies niet controleren (restrisico): gebruik altijd een nieuw formulier en nooit het papier van de andere sleutel."
    const val PAIR_INFO = "Koppel de sleutel daarna op de laptop in Chrome, op scherm S14 van HorseSafe."

    const val PRACTICE_INFO = "Je oefent het lezen van het papier, niet het typen op de laptop. Er wordt niets opgeslagen en de sleutel is niet nodig."
    const val PRACTICE_ADVICE = "Op de laptop: typ in Chrome groep voor groep met het papier ernaast. Na 2 fouten: stop en controleer de groepen hier. Na 3 fouten: steek de sleutel opnieuw in. Gebruik nooit een webpagina als typtrainer."

    fun profileShort(p: Profile): String = when (p) {
        Profile.BIO_MAIN -> "Hoofdsleutel (Bio)"
        Profile.RECOVERY_YK5 -> "Noodsleutel (YubiKey 5)"
        Profile.RECOVERY_BIO -> "Noodsleutel (Bio zonder vinger)"
    }

    fun written(w: Written): String = when (w) {
        Written.PIN -> "Er staat een PIN op de sleutel."
        Written.MIN_PIN_LENGTH_63 -> "De minimale PIN-lengte 63 staat vast."
        Written.ALWAYS_UV -> "alwaysUv staat aan."
        Written.FINGERPRINTS -> "Er staan vingers op de sleutel."
    }

    fun formFactor(f: KeyFormFactor): String = when (f) {
        KeyFormFactor.UNKNOWN -> "onbekend"
        KeyFormFactor.USB_A_KEYCHAIN -> "USB-A sleutelhanger"
        KeyFormFactor.USB_A_NANO -> "USB-A nano"
        KeyFormFactor.USB_C_KEYCHAIN -> "USB-C sleutelhanger"
        KeyFormFactor.USB_C_NANO -> "USB-C nano"
        KeyFormFactor.USB_C_LIGHTNING -> "USB-C/Lightning"
        KeyFormFactor.USB_A_BIO -> "USB-A Bio"
        KeyFormFactor.USB_C_BIO -> "USB-C Bio"
    }

    /** Vingers voor M7; naam automatisch, bv. `R-wijs`. ASCII. */
    val fingerNames: List<Pair<String, String>> = listOf(
        "R-duim" to "Rechterduim", "R-wijs" to "Rechterwijsvinger", "R-middel" to "Rechtermiddelvinger",
        "R-ring" to "Rechterringvinger", "R-pink" to "Rechterpink",
        "L-duim" to "Linkerduim", "L-wijs" to "Linkerwijsvinger", "L-middel" to "Linkermiddelvinger",
        "L-ring" to "Linkerringvinger", "L-pink" to "Linkerpink",
    )

    const val LICENSES = """yubikit-android 3.0.1 (android, core, fido, management) — Apache License 2.0, © Yubico AB; NOTICE-bestand van Yubico van toepassing.
slf4j-api — MIT License, © QOS.ch.
AndroidX, Jetpack Compose, Kotlin en kotlinx.coroutines — Apache License 2.0, © The Android Open Source Project / JetBrains s.r.o.
Vertrouwensankers: Yubico FIDO-roots en de AAGUID-lijst (FIDO MDS3), gelijk aan de server."""
}
