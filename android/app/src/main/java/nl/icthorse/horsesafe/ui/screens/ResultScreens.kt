package nl.icthorse.horsesafe.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.report.Report
import nl.icthorse.horsesafe.ui.CodeTarget
import nl.icthorse.horsesafe.ui.HorseSafeViewModel
import nl.icthorse.horsesafe.ui.Screen
import nl.icthorse.horsesafe.ui.Texts
import nl.icthorse.horsesafe.ui.TrustInfo
import nl.icthorse.horsesafe.ui.UiState
import nl.icthorse.horsesafe.ui.components.Body
import nl.icthorse.horsesafe.ui.components.CheckList
import nl.icthorse.horsesafe.ui.components.MessageBar
import nl.icthorse.horsesafe.ui.components.Panel
import nl.icthorse.horsesafe.ui.components.PinKeypad
import nl.icthorse.horsesafe.ui.components.Primary
import nl.icthorse.horsesafe.ui.components.ScreenFrame
import nl.icthorse.horsesafe.ui.components.SectionTitle
import nl.icthorse.horsesafe.ui.components.Secondary
import nl.icthorse.horsesafe.ui.components.Small
import nl.icthorse.horsesafe.ui.theme.HsColors

/** M9 Keuring: resultaten en vergelijking met het vorige rapport; elk verschil is rood. */
@Composable
fun M9Keuring(u: UiState, vm: HorseSafeViewModel, onExport: () -> Unit) {
    val r = u.report
    ScreenFrame(Screen.M9_KEURING, "Keuring", bottom = {
        if (r != null) Secondary("Exporteren…") { onExport() }
        if (u.secretsTouched) Primary("Afsluiten") { vm.quit() } else Primary("Klaar") { vm.backToStart() }
    }) {
        MessageBar(u.message) { vm.clearMessage() }
        if (r == null) {
            Body("Geen rapport.")
            return@ScreenFrame
        }
        ReportHeader(r)
        val c = u.comparison
        Panel(border = when {
            c == null || !c.hasBasis -> HsColors.Orange
            c.differences.isNotEmpty() -> HsColors.Red
            else -> HsColors.Green
        }) {
            SectionTitle("Vergelijking met het vorige rapport")
            when {
                c == null || !c.hasBasis -> Body("Geen vergelijkingsbasis: er is geen eerder rapport voor deze rol. Importeer een eerder rapport via Rapporten.", HsColors.Orange)
                c.differences.isEmpty() -> Body("Gelijk aan het rapport van ${c.previous?.createdAt}.", HsColors.Green)
                else -> c.differences.forEach { Body("• Verschil: $it", HsColors.Red) }
            }
            c?.notComparable?.forEach { Small("Niet te vergelijken: $it", HsColors.Orange) }
        }
        r.stop?.let { name ->
            val s = Stop.entries.firstOrNull { it.name == name }
            Panel(border = HsColors.Red) { Body(s?.tekst ?: name, HsColors.Red); s?.let { Small(it.advies) } }
        }
        SectionTitle("Eisen")
        CheckList(r.checks)
    }
}

@Composable
private fun ReportHeader(r: Report) {
    Panel {
        SectionTitle(Texts.profileShort(r.profile))
        Small("${r.kind.name.lowercase().replace('_', ' ')} · ${r.createdAt}")
        Small("Firmware ${r.firmware ?: "onbekend"} · ${r.keyClass}/${r.variant} · ${r.transport}")
        Small("Minimum PIN-lengte: ${r.minPinLength ?: "?"} · PIN-pogingen: ${r.pinRetries ?: "?"}" + (r.uvRetries?.let { " · vingerpogingen: $it" } ?: ""))
        r.residentCredentials?.let { Small("Resident credentials: $it") }
        r.fingerCount?.let { Small("Vingers: $it ${r.fingerNames?.joinToString(", ", "(", ")") ?: ""}") }
        r.attestationOk?.let { Small(if (it) "Echtheid aangetoond" else "Echtheid NIET aangetoond", if (it) HsColors.Green else HsColors.Red) }
        Small(if (r.serialHmac != null) "Serienummer: als HMAC vastgelegd" else "Serienummer: niet beschikbaar", if (r.serialHmac != null) HsColors.Muted else HsColors.Orange)
    }
}

/** M10 Rapport: het actuele rapport (export, afsluiten) of het archief (import, bekijken). */
@Composable
fun M10Report(u: UiState, vm: HorseSafeViewModel, onExport: () -> Unit, onImport: () -> Unit) {
    val r = u.report
    val setupDone = u.finalReport
    ScreenFrame(Screen.M10_REPORT, if (r != null && setupDone) "Rapport" else "Rapporten", bottom = {
        if (r != null && setupDone) {
            Secondary("Exporteren…") { onExport() }
            Primary("Afsluiten") { vm.quit() }
        } else {
            Secondary("Importeren…") { onImport() }
            Primary("Terug naar start") { vm.backToStart() }
        }
    }) {
        MessageBar(u.message) { vm.clearMessage() }
        if (r != null && setupDone) {
            Body(
                when (r.kind) {
                    nl.icthorse.horsesafe.report.ReportKind.PIN_CHANGE -> "De PIN is gewijzigd. Vernietig het oude papier en werk de vault-invoer bij; de app schrijft zelf niet naar de vault."
                    nl.icthorse.horsesafe.report.ReportKind.FINGERS -> "De vingers zijn bijgewerkt."
                    else -> "De sleutel is ingericht."
                } + " Dit rapport bevat geen PIN, geen token en geen serienummer.",
                HsColors.Green,
            )
            ReportHeader(r)
            if (r.profile != Profile.BIO_MAIN && (r.kind == nl.icthorse.horsesafe.report.ReportKind.SETUP || r.kind == nl.icthorse.horsesafe.report.ReportKind.RESUME || r.kind == nl.icthorse.horsesafe.report.ReportKind.PIN_CHANGE)) CodeEntry(u, vm)
            val c = u.comparison
            if (c != null && c.hasBasis && c.differences.isNotEmpty()) c.differences.forEach { Small("Verschil met vorig rapport: $it", HsColors.Red) }
            SectionTitle("Eisen")
            CheckList(r.checks)
            Small(Texts.QUIT_INFO)
            if (r.kind == nl.icthorse.horsesafe.report.ReportKind.SETUP || r.kind == nl.icthorse.horsesafe.report.ReportKind.RESUME) Small(Texts.PAIR_INFO)
            if (r.kind == nl.icthorse.horsesafe.report.ReportKind.SETUP || r.kind == nl.icthorse.horsesafe.report.ReportKind.RESUME ||
                r.kind == nl.icthorse.horsesafe.report.ReportKind.PIN_CHANGE
            ) Small(Texts.DIFFERENT_PINS, HsColors.Orange)
            Small("Vernietig een eventueel ouder formulier van deze sleutel en bewaar het nieuwe op de afgesproken plek.")
        } else {
            Body("Rapporten staan alleen in de app (geen back-up). Exporteer ze via de opslagkiezer en importeer ze na een herinstallatie of op een nieuwe telefoon, zodat de kwartaalvergelijking een basis heeft.")
            if (u.archiveRejected > 0) Small("${u.archiveRejected} bestand(en) voldeden niet aan het schema en zijn genegeerd.", HsColors.Orange)
            if (u.archive.isEmpty()) Small("Nog geen rapporten.")
            u.archive.forEach { a ->
                Panel(Modifier.clickable { vm.openArchived(a) }) {
                    Body("${Texts.profileShort(a.profile)} · ${a.kind.name.lowercase().replace('_', ' ')}")
                    Small(a.createdAt + if (a.stop != null) " · gestopt" else "")
                }
            }
        }
    }
}

/** Codes van de verzegelde zak en de papierlocatie (noodsleutel), met het eigen toetsenblok. */
@Composable
private fun CodeEntry(u: UiState, vm: HorseSafeViewModel) {
    Panel {
        SectionTitle("Codes (zelf gekozen)")
        Small("Alleen een code, geen beschrijving van de plek. Tekens uit het PIN-alfabet, maximaal 12.")
        Body("Zak: ${u.sealCode.ifEmpty { "—" }}", if (u.codeTarget == CodeTarget.SEAL) HsColors.Accent else HsColors.OnSurface)
        Body("Papierlocatie: ${u.paperLocationCode.ifEmpty { "—" }}", if (u.codeTarget == CodeTarget.PAPER) HsColors.Accent else HsColors.OnSurface)
        if (u.reportSaved) {
            Small("Het rapport is bewaard; de codes liggen vast.")
            return@Panel
        }
        when (u.codeTarget) {
            null -> {
                Secondary("Zakcode invoeren") { vm.openCodeEntry(CodeTarget.SEAL) }
                Secondary("Code papierlocatie invoeren") { vm.openCodeEntry(CodeTarget.PAPER) }
                Secondary("Codes vastleggen en rapport bewaren") { vm.saveReportOnce() }
            }
            else -> {
                PinKeypad(enabled = true, onKey = { vm.codeKey(it) }, onDelete = { vm.codeDelete() })
                Secondary("Klaar") { vm.openCodeEntry(null) }
            }
        }
    }
}

/** M11 Stop: reden, wat al op de sleutel staat, wat je nu doet. */
@Composable
fun M11Stop(u: UiState, vm: HorseSafeViewModel) {
    val st = u.machine as? State.Stopped
    val stop = st?.stop ?: u.localStop ?: Stop.INTERNAL_ERROR
    ScreenFrame(Screen.M11_STOP, "Gestopt", bottom = {
        if (u.secretsTouched) Primary("Afsluiten") { vm.quit() }
        else Primary("Terug naar start") { vm.backToStart() }
    }) {
        Panel(border = HsColors.Red, background = HsColors.RedSurface) {
            SectionTitle("Waarom")
            Body(stop.tekst)
            SectionTitle("Wat je nu doet")
            Body(stop.advies)
        }
        Panel {
            SectionTitle("Wat al op de sleutel staat")
            val w = st?.written.orEmpty()
            if (w.isEmpty()) Body("Niets: de sleutel is niet gewijzigd.", HsColors.Green)
            w.forEach { Body("• " + Texts.written(it)) }
            if ((st?.fingers ?: 0) > 0) Small("Vingers op de sleutel: ${st?.fingers}")
        }
        Small("Een reset buiten de app (Yubico Authenticator of ykman) wist alles op de sleutel. Doe dat alleen bij de testsleutel. Na een stop doet de app niets meer op de sleutel.")
        if (u.secretsTouched) Small(Texts.QUIT_INFO)
        if (u.checks.isNotEmpty()) {
            SectionTitle("Beoordeling")
            CheckList(u.checks)
        }
    }
}

/** M12 Over: versie, licenties, vertrouwensankers en ondertekening. */
@Composable
fun M12About(vm: HorseSafeViewModel, appVersion: String, trust: TrustInfo, signerSha256: String?, debug: Boolean) {
    ScreenFrame(Screen.M12_ABOUT, "Over HorseSafe", bottom = { Primary("Terug naar start") { vm.backToStart() } }) {
        Panel {
            SectionTitle("HorseSafe $appVersion" + if (debug) " (debug-build)" else "")
            Small("Deel 1: YubiKey inrichten en keuren. Geen internet-permissie, geen server, geen back-up.")
        }
        Panel(border = if (trust.error != null) HsColors.Red else null) {
            SectionTitle("Vertrouwensankers")
            trust.error?.let { Body(it, HsColors.Red) }
            Small("Yubico FIDO-roots (SHA-256): ${trust.rootsSha256}")
            Small("Ankers geladen: ${trust.anchorCount}")
            Small("AAGUID-lijst (SHA-256): ${trust.aaguidsSha256}")
            Small("AAGUID's op de lijst: ${trust.allowlistSize}")
        }
        Panel {
            SectionTitle("Ondertekening")
            Small("Signer SHA-256: ${signerSha256 ?: "niet te lezen"}")
            Small("Vergelijk met de waarde in de README van android/ en in HorseAPK.")
        }
        Panel {
            SectionTitle("Licenties")
            Texts.LICENSES.lines().forEach { Small(it) }
        }
    }
}
