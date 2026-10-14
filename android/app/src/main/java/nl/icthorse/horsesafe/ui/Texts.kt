package nl.icthorse.horsesafe.ui

import nl.icthorse.horsesafe.biometric.BioAvailability
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
AndroidX (o.a. biometric 1.2.0-alpha05, fragment), Jetpack Compose, Kotlin en kotlinx.coroutines — Apache License 2.0, © The Android Open Source Project / JetBrains s.r.o.
zxing-android-embedded 4.3.0 en ZXing core 3.4.1 — Apache License 2.0, © JourneyApps / ZXing authors.
Vertrouwensankers: Yubico FIDO-roots en de AAGUID-lijst (FIDO MDS3), gelijk aan de server."""

    // F8 Sleutel wissen (M13, 0.3.1)
    const val RESET_WARNING = "Wissen haalt alles van het FIDO-deel van de sleutel: alle passkeys en koppelingen, de PIN, de vingers, de minimale PIN-lengte en alwaysUv. Daarna werkt de sleutel nergens meer, ook niet in HorseSafe. Is dit je enige gekoppelde sleutel, dan sluit je jezelf buiten."
    const val RESET_CONNECT = "Sluit de sleutel aan die je wilt wissen (USB, of NFC bij een YubiKey 5). De app leest eerst alleen uit wat erop staat."
    const val RESET_LOSES = "Alle FIDO-credentials (ook voor andere sites), de PIN, de vingers, de minimale PIN-lengte 63 en alwaysUv. PIV, OATH en OpenPGP blijven staan. Er is geen herstel."
    const val RESET_REPLUG_USB = "Haal de sleutel eruit en steek hem meteen weer in. Vraagt Android om USB-toestemming, tik dan direct op OK."
    const val RESET_REPLUG_NFC = "Haal de sleutel weg van de telefoon en houd hem er meteen weer tegen. Houd hem daarna stil tegen de telefoon."
    const val RESET_WINDOW = "Een YubiKey accepteert wissen alleen in de eerste seconden na het aansluiten. De app controleert eerst dat het dezelfde sleutel is (serienummer); bij een andere sleutel wordt er niets gewist."
    const val RESET_TOUCH = "Raak het gouden contact van de sleutel aan om het wissen te bevestigen (bij NFC: stil tegen de telefoon houden)."
    const val RESET_TOUCH_BIO = "Raak de vingerafdruksensor van de YubiKey Bio aan om het wissen te bevestigen."
    const val RESET_DONE = "Op de sleutel staan geen PIN en geen vingers meer. Je kunt hem nu opnieuw inrichten."
    const val RESET_DONE_SERVER = "Was deze sleutel gekoppeld in HorseSafe (Instellingen > Hardwaresleutels), verwijder die koppeling daar; de app kan dat niet zelf."

    // Deel 2: telefoon koppelen (M14-M19, 0.3.4)
    const val PAIR_INTRO = "Koppel deze telefoon aan je HorseSafe-account. Daarna kan de telefoon een verzegelde kopie van je ontgrendelmateriaal openen, alleen met je vingerafdruk. Een toestel-PIN of patroon telt nooit."
    val PAIR_STEPS: List<String> = listOf(
        "Open op de laptop je kluis en kies daar \"Telefoon koppelen\". Er verschijnt een QR-code.",
        "Scan die QR-code met deze app.",
        "Leg twee keer je vinger op de sensor: eerst om de sleutel van deze telefoon te beschermen, dan om de koppeling te ondertekenen.",
        "Vergelijk de 6 cijfers op de telefoon met die op de laptop en klik op de laptop op Klopt.",
    )
    const val PAIR_TWO_TOUCHES = "Je legt zo twee keer je vinger op de sensor. Annuleren breekt het koppelen af; er blijft dan niets op de telefoon staan."
    const val PAIR_NETWORK = "Koppelen gebruikt internet, alleen naar de HorseSafe-server. Het inrichten en keuren van YubiKeys blijft zonder netwerk werken."
    const val PAIR_REPLACE = "Opnieuw koppelen wist de huidige koppeling en de sleutels op deze telefoon. Verwijder daarna het oude toestel in HorseSafe op de laptop."
    const val PAIR_SAS_HELP = "Staan op de laptop dezelfde 6 cijfers? Klik daar op Klopt. Zijn ze anders, klik dan op Klopt niet: dan is er een ander toestel gescand of is er geknoeid. De telefoon wacht tot de laptop heeft gekozen."
    const val PAIR_TRIAL_INFO = "De proef haalt de verzegelde kopie op, opent hem met je vinger en controleert alleen de vorm. De inhoud wordt niet getoond en niet bewaard."
    const val PAIR_BIO_RULE = "HorseSafe accepteert alleen een sterke vingerafdruk (Android-klasse 3). Gezichtsherkenning, PIN, patroon of wachtwoord van het toestel tellen niet."
    const val PAIR_REPAIR = "De vingerafdrukken op dit toestel zijn gewijzigd (of de sleutels zijn verdwenen). De koppelsleutels zijn daardoor ongeldig en alles van de koppeling is van deze telefoon gewist."
    const val PAIR_REPAIR_LAPTOP = "Verwijder het oude toestel in HorseSafe op de laptop en koppel deze telefoon opnieuw."

    fun bioBlocked(b: BioAvailability): String = when (b) {
        BioAvailability.OK -> "Vingerafdruk is beschikbaar."
        BioAvailability.NONE_ENROLLED -> "Stel eerst een vingerafdruk in (Instellingen > Biometrie en beveiliging > Vingerafdrukken) en kom dan terug."
        BioAvailability.NO_HARDWARE -> "Deze telefoon heeft geen sterke vingerafdruksensor. Koppelen kan op dit toestel niet."
        BioAvailability.UNAVAILABLE -> "De vingerafdruksensor is nu niet beschikbaar. Probeer het straks opnieuw."
        BioAvailability.UPDATE_REQUIRED -> "De vingerafdruksensor vraagt eerst een beveiligingsupdate van het toestel."
        BioAvailability.UNSUPPORTED -> "Een sterke vingerafdruk (klasse 3) is op dit toestel niet beschikbaar."
    }

    /** "123456" → "123 456" (leesbaarder; de cijfers zelf veranderen niet). */
    fun sasGrouped(sas: String): String = if (sas.length == 6) sas.substring(0, 3) + " " + sas.substring(3) else sas
}
