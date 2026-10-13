package nl.icthorse.horsesafe.ui.screens

import androidx.compose.runtime.Composable
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.ui.HorseSafeViewModel
import nl.icthorse.horsesafe.ui.Purpose
import nl.icthorse.horsesafe.ui.Screen
import nl.icthorse.horsesafe.ui.Texts
import nl.icthorse.horsesafe.ui.UiState
import nl.icthorse.horsesafe.ui.components.Body
import nl.icthorse.horsesafe.ui.components.CheckList
import nl.icthorse.horsesafe.ui.components.MenuCard
import nl.icthorse.horsesafe.ui.components.MessageBar
import nl.icthorse.horsesafe.ui.components.Panel
import nl.icthorse.horsesafe.ui.components.SectionTitle
import nl.icthorse.horsesafe.ui.components.Secondary
import nl.icthorse.horsesafe.ui.components.Small
import nl.icthorse.horsesafe.ui.theme.HsColors

/** M0 Start: versie, omgevingsoordeel en menukaarten. "Sleutel wissen" staat bewust onderaan (0.3.1). */
@Composable
fun M0Start(u: UiState, vm: HorseSafeViewModel, appVersion: String) {
    val pick = u.pickProfileFor
    if (pick != null) {
        ProfilePicker(pick, vm)
        return
    }
    ScreenFrame0(u, vm, appVersion)
}

@Composable
private fun ScreenFrame0(u: UiState, vm: HorseSafeViewModel, appVersion: String) {
    nl.icthorse.horsesafe.ui.components.ScreenFrame(Screen.M0_START, "HorseSafe") {
        Small("Versie $appVersion · alleen lokaal, geen internet")
        MessageBar(u.message) { vm.clearMessage() }
        Panel(border = if (u.env.blocksSecrets) HsColors.Red else null) {
            SectionTitle("Omgeving")
            if (u.env.violations.isEmpty() && u.env.warnings.isEmpty()) {
                Body("In orde: geen toegankelijkheidsdienst, geen gesplitst scherm, geen extern scherm, geen opname.")
            }
            u.env.violations.forEach { Body("• ${it.tekst} ${it.advies}", HsColors.Red) }
            if (u.env.blocksSecrets) Small("De schermen met een PIN zijn geblokkeerd tot dit is opgelost. Herkennen en keuren zonder PIN werken wel.")
            CheckList(u.env.warnings)
        }
        MenuCard("Nieuwe hoofdsleutel (YubiKey Bio)", "PIN van 63 tekens, keuring, minimum 63, alwaysUv, 2-3 vingers") { vm.start(Purpose.SETUP_NEW, Profile.BIO_MAIN) }
        MenuCard("Nieuwe noodsleutel", "YubiKey 5 NFC, of een Bio zonder vinger") { vm.choose(Purpose.SETUP_NEW) }
        MenuCard("Inrichting hervatten", "Gedeeltelijk ingerichte sleutel afmaken met de PIN van papier") { vm.choose(Purpose.SETUP_RESUME) }
        MenuCard("Keuren zonder PIN", "Elk kwartaal; USB of NFC; alleen lezen") { vm.choose(Purpose.KEURING_ZONDER_PIN) }
        MenuCard("Keuren met PIN", "Vingerlijst, resident credentials en echtheid; PIN van papier") { vm.choose(Purpose.KEURING_MET_PIN) }
        MenuCard("PIN wijzigen", "Nieuwe PIN van 63 tekens; minimum en alwaysUv blijven ongemoeid") { vm.choose(Purpose.PIN_CHANGE) }
        MenuCard("Vingers beheren", "Hoofdsleutel: toevoegen, hernoemen, verwijderen, testaanraking") { vm.choose(Purpose.FINGERS) }
        MenuCard("Oefenen", "PIN-groepen van papier controleren met de controletekens, zonder sleutel") { vm.choose(Purpose.PRACTICE) }
        MenuCard("Sleutel wissen", "Al ingerichte sleutel helemaal wissen (FIDO-reset); onomkeerbaar") { vm.choose(Purpose.RESET) }
        MenuCard("Rapporten", "Bekijken, exporteren en importeren (opslagkiezer)") { vm.openReports() }
        MenuCard("Over HorseSafe", "Licenties, vertrouwensankers en ondertekening") { vm.openAbout() }
    }
}

@Composable
private fun ProfilePicker(purpose: Purpose, vm: HorseSafeViewModel) {
    nl.icthorse.horsesafe.ui.components.ScreenFrame(Screen.M0_START, purpose.nl, bottom = { Secondary("Terug") { vm.pickProfile(null) } }) {
        Body("Welke sleutel?")
        val options = when (purpose) {
            Purpose.SETUP_NEW -> listOf(Profile.RECOVERY_YK5, Profile.RECOVERY_BIO)
            else -> Profile.entries.toList()
        }
        options.forEach { p -> MenuCard(Texts.profileShort(p), p.nl) { vm.pickProfile(p) } }
    }
}
