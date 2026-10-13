package nl.icthorse.horsesafe.flow

/**
 * Harde stop met Nederlandse tekst ([tekst]) en advies ([advies]) voor M11. Na een stop volgt geen
 * schrijfactie meer. Oranje meldingen (bv. U2F_V2 na alwaysUv, kritiek 10) zijn GEEN Stop.
 */
enum class Stop(val tekst: String, val advies: String) {
    // F0 omgeving
    ENV_ACCESSIBILITY("Er staat een toegankelijkheidsdienst aan die mee kan lezen.", "Zet de dienst uit in Instellingen > Toegankelijkheid en start opnieuw."),
    ENV_ADB("Ontwikkelaarsopties of foutopsporing (ADB via USB of draadloos) staan aan.", "Zet de ontwikkelaarsopties helemaal uit en start opnieuw."),
    ENV_MULTI_WINDOW("De app draait in gesplitst scherm, zwevend venster of beeld-in-beeld.", "Open HorseSafe schermvullend."),
    ENV_EXTERNAL_DISPLAY("De app draait op een ander scherm of in DeX/desktopmodus.", "Stop DeX of de schermkoppeling en gebruik alleen het telefoonscherm."),
    ENV_SCREEN_RECORDING("Het scherm wordt opgenomen of gedeeld.", "Stop de opname of het delen en start opnieuw."),

    // F1 herkennen
    MULTIPLE_KEYS("Er is meer dan één sleutel aangesloten.", "Sluit precies één YubiKey direct aan, zonder hub of dock."),
    KEY_REMOVED("De sleutel werd losgekoppeld.", "Bekijk op dit scherm wat al op de sleutel staat en volg het advies."),
    NO_FIDO_2_1("De sleutel ondersteunt FIDO 2.1 niet.", "Gebruik een YubiKey met firmware 5.7 of nieuwer."),
    MISSING_SET_MIN_PIN_LENGTH("De sleutel kan geen minimale PIN-lengte vastzetten.", "Gebruik een YubiKey met firmware 5.7 of nieuwer."),
    MISSING_AUTHNR_CFG("De sleutel ondersteunt geen configuratie (authnrCfg).", "Gebruik een YubiKey met firmware 5.7 of nieuwer."),
    MISSING_ALWAYS_UV("De sleutel kent de instelling alwaysUv niet.", "Gebruik een YubiKey met firmware 5.7 of nieuwer."),
    MAX_RPIDS_TOO_LOW("De sleutel kan de minimale PIN-lengte aan geen enkele site melden.", "Gebruik een andere YubiKey."),
    FIRMWARE_UNKNOWN("De firmwareversie is niet vast te stellen.", "Sluit de sleutel via USB aan en probeer opnieuw."),
    FIRMWARE_TOO_OLD_BIO("De firmware van deze YubiKey Bio is ouder dan 5.7.2 (YSA-2024-03).", "Deze sleutel is niet bruikbaar; schaf een nieuwe YubiKey Bio aan."),
    FIRMWARE_TOO_OLD_YK5("De firmware van deze YubiKey 5 is ouder dan 5.7.0 (YSA-2024-03).", "Deze sleutel is niet bruikbaar; schaf een nieuwe YubiKey 5 aan."),
    AAGUID_NOT_ALLOWED("Dit sleuteltype staat niet op de lijst van toegestane YubiKeys.", "Gebruik een YubiKey Bio (hoofdsleutel) of YubiKey 5 (noodsleutel)."),
    CLASS_MISMATCH("Dit sleuteltype past niet bij de gekozen rol.", "Kies de juiste rol of sluit de juiste sleutel aan."),
    MAX_PIN_LENGTH_UNKNOWN("De sleutel meldt niet hoe lang een PIN mag zijn.", "Niet doorgaan tot dit op de testsleutel is gemeten (open vraag 4)."),
    MAX_PIN_LENGTH_TOO_SHORT("De sleutel accepteert geen PIN van 63 tekens.", "Bij een Bio Multi-protocol: zet PIV uit met Yubico Authenticator of ykman, of gebruik een FIDO Edition."),

    // Nieuw-sleutelgate / hervatten
    PIN_ALREADY_SET("Op deze sleutel staat al een PIN.", "Gebruik \"PIN wijzigen\" of \"Inrichting hervatten\". Of kies \"Sleutel wissen\" om opnieuw te beginnen; alles erop gaat verloren."),
    BIO_ALREADY_ENROLLED("Op deze sleutel staan al vingers.", "Kies \"Sleutel wissen\" als je deze sleutel opnieuw wilt inrichten; alles erop gaat verloren."),
    FORCE_PIN_CHANGE("De sleutel eist eerst een PIN-wijziging.", "Kies \"Sleutel wissen\" als je deze sleutel opnieuw wilt inrichten; alles erop gaat verloren."),
    RESUME_NOT_ALLOWED("Deze sleutel komt niet in aanmerking voor hervatten.", "Controleer met \"Keuren zonder PIN\" wat er op de sleutel staat."),
    KEY_ALREADY_USED("De sleutel is al gebruikt of gemanipuleerd (resident credentials of vingers aanwezig).", "Is het je eigen sleutel, kies dan \"Sleutel wissen\"; alles erop gaat verloren. Anders: gebruik deze sleutel niet."),
    /** Toegevoegd in de flow-fase (A-5): herstart vóór setPin; de PIN van deze poging is waardeloos. */
    RESTART_BEFORE_PIN("De app werd herstart voordat de PIN op de sleutel stond; er is niets op de sleutel gezet.", "Vernietig het formulier van deze poging en begin opnieuw; de app maakt dan een nieuwe PIN."),
    /** Review: setPin kreeg een herstelbare fout (time-out) en bij opnieuw proberen bleek er al een PIN te staan. */
    PIN_STATE_UNKNOWN("Het antwoord op \"PIN zetten\" ging verloren; bij opnieuw proberen stond er al een PIN op de sleutel. Dat is waarschijnlijk de PIN van dit formulier.", "Bewaar dit formulier. Kies \"Inrichting hervatten\" en voer de PIN van dit papier in; vernietig een eventueel ouder formulier."),
    /** Review: een YubiKey 5 zonder PIN met alwaysUv aan wijkt af van de fabrieksstand. */
    YK5_ALWAYS_UV_PRESET("Op deze YubiKey 5 staat alwaysUv al aan terwijl er nog geen PIN is; de sleutel is dus al eerder ingesteld.", "Is het je eigen sleutel, kies dan \"Sleutel wissen\" en richt hem daarna opnieuw in."),
    PROCESS_RESTARTED("De app is opnieuw gestart na het zetten van de PIN.", "Kies \"Inrichting hervatten\" met de PIN van papier; vernietig een eventueel ouder formulier."),

    // PIN
    PIN_POLICY_MPE_PIV("De sleutel weigert een PIN van 63 tekens; dit is waarschijnlijk een Bio Multi-protocol met PIV aan (PIN maximaal 8 tekens).", "Zet PIV uit met Yubico Authenticator of ykman (wissen in de app zet PIV niet uit)."),
    PIN_READBACK_FAILED("Na het zetten van de PIN klopt de teruglezing niet.", "Niet verder gaan; bekijk op dit scherm wat al op de sleutel staat."),
    PIN_RETRIES_LOW("Er zijn nog maar 3 of minder PIN-pogingen over.", "Controleer eerst het papier met \"Oefenen\"; steek de sleutel opnieuw in."),
    PIN_BLOCKED("De PIN is geblokkeerd.", "Kies \"Sleutel wissen\" (start de app zo nodig opnieuw); alle gegevens erop gaan verloren."),
    /** Toegevoegd in de flow-fase (kritiek 16): complexiteitsbeleid weigert de PIN vóór setPin; er staat nog niets op de sleutel. */
    PIN_POLICY_COMPLEXITY("De sleutel weigert deze PIN door zijn complexiteitsbeleid; er is nog niets op de sleutel gezet.", "Vernietig het formulier van deze poging en begin opnieuw; de app maakt dan een nieuwe PIN."),

    // Attestation
    ATTEST_NOT_PACKED("De sleutel bewijst zijn echtheid niet (geen packed attestation met certificaat).", "Gebruik deze sleutel niet; hij is mogelijk nagemaakt."),
    ATTEST_CHAIN_INVALID("Het certificaat van de sleutel leidt niet naar Yubico.", "Gebruik deze sleutel niet; hij is mogelijk nagemaakt."),
    ATTEST_AAGUID_MISMATCH("Het sleuteltype in het certificaat klopt niet met wat de sleutel meldt.", "Gebruik deze sleutel niet."),
    ATTEST_FLAGS_INVALID("De vlaggen in het keuringsbewijs kloppen niet.", "Gebruik deze sleutel niet."),
    ATTEST_RP_ID_HASH("Het keuringsbewijs hoort niet bij deze keuring.", "Gebruik deze sleutel niet; mogelijk zit er iets tussen telefoon en sleutel."),
    ATTEST_ALGORITHM("De sleutel gebruikt een onverwacht algoritme.", "Gebruik deze sleutel niet."),

    // Config
    MIN_PIN_LENGTH_READBACK_FAILED("De minimale PIN-lengte van 63 staat niet (goed) vast.", "Niet verder gaan; bekijk op dit scherm wat al op de sleutel staat."),
    ALWAYS_UV_READBACK_FAILED("alwaysUv staat na het aanzetten niet aan.", "Niet verder gaan; bekijk op dit scherm wat al op de sleutel staat."),

    // Vingers
    FINGER_COUNT_INVALID("Het aantal vingers klopt niet met de rol.", "Hoofdsleutel: 2 of 3 vingers. Noodsleutel: geen vinger."),
    /** Review: na te veel mislukte vingermatches (CTAP 0x3C). */
    UV_BLOCKED("De vingerpogingen zijn op en konden niet met de PIN worden hersteld.", "Steek de sleutel opnieuw in en probeer het opnieuw; lukt het niet, kies dan \"Vingers beheren\" of \"Inrichting hervatten\"."),
    /** Review: F6 alleen voor de hoofdsleutel; een noodsleutel-Bio mag geen vinger krijgen. */
    RECOVERY_KEY_NO_FINGERS("Dit is de noodsleutel (of de app kan niet vaststellen dat het de hoofdsleutel is); daarop hoort geen vinger.", "Gebruik \"Vingers beheren\" alleen met de hoofdsleutel. Is dit wel de hoofdsleutel, keur hem dan eerst met \"Keuren zonder PIN\" als hoofdsleutel."),
    RECOVERY_BIO_HAS_FINGER("Op de noodsleutel-Bio staat een vinger, of dat is niet vast te stellen.", "Kies \"Sleutel wissen\" en richt hem daarna opnieuw in."),

    // Wissen (F8, 0.3.1)
    RESET_NO_SERIAL("De app kan het serienummer van deze sleutel niet lezen en dus niet controleren dat straks dezelfde sleutel gewist wordt.", "Er is niets gewist. Wis deze sleutel met Yubico Authenticator of ykman fido reset."),
    RESET_OTHER_KEY("Na opnieuw insteken kwam er een andere sleutel dan je bevestigde; er is niets gewist.", "Begin opnieuw met \"Sleutel wissen\" en houd alleen de juiste sleutel bij de hand."),
    RESET_READBACK_FAILED("Na het wissen staat er nog een PIN of een vinger op de sleutel.", "Gebruik deze sleutel niet; wis hem met Yubico Authenticator of ykman en keur hem daarna."),

    // Keuren
    KEY_SWAPPED("Dit is niet dezelfde sleutel als in het vorige rapport.", "Controleer welke sleutel je in handen hebt; meld een onverwachte wissel."),

    /** Toegevoegd in de flow-fase: de gebruiker brak af (Annuleren/Afsluiten vóór het rapport). */
    CANCELLED("Je hebt de bewerking afgebroken.", "Bekijk op dit scherm wat al op de sleutel staat; staat er al een PIN, kies dan later \"Inrichting hervatten\"."),

    INTERNAL_ERROR("Interne fout in de app.", "Sluit de app af en begin opnieuw; er is niets opgeslagen."),
    ;

    companion object {
        /** Stops waarbij M11 "Sleutel wissen" aanbiedt (alleen als er in dit proces nog geen geheim was). */
        val WIPE_OFFERED: Set<Stop> = setOf(
            PIN_ALREADY_SET, BIO_ALREADY_ENROLLED, FORCE_PIN_CHANGE, KEY_ALREADY_USED, YK5_ALWAYS_UV_PRESET,
            PIN_BLOCKED, RECOVERY_BIO_HAS_FINGER, RESUME_NOT_ALLOWED,
        )
    }
}
