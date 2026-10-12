package nl.icthorse.horsesafe.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.SetupMode
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Written
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.ui.EntryMode
import nl.icthorse.horsesafe.ui.HorseSafeViewModel
import nl.icthorse.horsesafe.ui.KeyPresence
import nl.icthorse.horsesafe.ui.Purpose
import nl.icthorse.horsesafe.ui.Screen
import nl.icthorse.horsesafe.ui.Texts
import nl.icthorse.horsesafe.ui.UiState
import nl.icthorse.horsesafe.ui.components.BlockedPanel
import nl.icthorse.horsesafe.ui.components.Body
import nl.icthorse.horsesafe.ui.components.CheckList
import nl.icthorse.horsesafe.ui.components.GroupDots
import nl.icthorse.horsesafe.ui.components.GroupReveal
import nl.icthorse.horsesafe.ui.components.MessageBar
import nl.icthorse.horsesafe.ui.components.Panel
import nl.icthorse.horsesafe.ui.components.PinKeypad
import nl.icthorse.horsesafe.ui.components.Primary
import nl.icthorse.horsesafe.ui.components.RetryBanner
import nl.icthorse.horsesafe.ui.components.ScreenFrame
import nl.icthorse.horsesafe.ui.components.SectionTitle
import nl.icthorse.horsesafe.ui.components.Secondary
import nl.icthorse.horsesafe.ui.components.Small
import nl.icthorse.horsesafe.ui.components.StepList
import nl.icthorse.horsesafe.ui.components.TickRow
import nl.icthorse.horsesafe.ui.stepsFor
import nl.icthorse.horsesafe.ui.theme.HsColors

/**
 * Afbreken/terug-knop: vóór een geheim terug naar start; daarna "Afbreken" (de bewerking stopt en M11
 * toont wat er op de sleutel staat) of, als er niets meer loopt, "Afsluiten".
 */
@Composable
internal fun CancelButton(u: UiState, vm: HorseSafeViewModel) {
    when {
        !u.secretsTouched -> Secondary("Terug naar start", enabled = !u.busy) { vm.backToStart() }
        u.purpose == Purpose.PRACTICE && !u.busy -> Secondary("Afsluiten") { vm.quit() }
        else -> Secondary("Afbreken") { vm.cancel() }
    }
}

/** M1 Checklist: afvinken vóór er een sleutel of PIN in beeld komt. */
@Composable
fun M1Checklist(u: UiState, vm: HorseSafeViewModel) {
    ScreenFrame(Screen.M1_CHECKLIST, "Checklist", bottom = {
        Primary("Verder: sleutel aansluiten", enabled = u.checklist.size == Texts.checklist.size) { vm.checklistDone() }
        Secondary("Terug naar start") { vm.backToStart() }
    }) {
        u.profile?.let { Small(Texts.profileShort(it) + if (u.purpose == Purpose.SETUP_RESUME) " · hervatten" else "") }
        Body("Vink alles af. De app controleert zelf ook de omgeving, maar niet alles is te meten.")
        Texts.checklist.forEachIndexed { i, t -> TickRow(t, i in u.checklist) { vm.toggleChecklist(i) } }
        if (u.env.blocksSecrets) BlockedPanel(u.env.violations.map { "${it.tekst} ${it.advies}" })
    }
}

/** M2 Sleutel aansluiten en herkennen. */
@Composable
fun M2Connect(u: UiState, vm: HorseSafeViewModel) {
    ScreenFrame(Screen.M2_CONNECT, "Sleutel aansluiten", bottom = { CancelButton(u, vm) }) {
        MessageBar(u.message) { vm.clearMessage() }
        Body(Texts.CONNECT_USB)
        if (u.profile == Profile.RECOVERY_YK5) Small(Texts.CONNECT_OTG)
        Small(Texts.CONNECT_DIALOG)
        if (u.purpose == Purpose.KEURING_ZONDER_PIN) Small(Texts.CONNECT_NFC)
        Panel {
            when (u.key) {
                KeyPresence.NONE -> Body("Wacht op een YubiKey…")
                KeyPresence.CONNECTED -> Body("Sleutel gevonden; bezig met herkennen…")
                KeyPresence.MULTIPLE -> Body("Er is meer dan één sleutel aangesloten. Haal ze allemaal los en sluit er één aan.", HsColors.Red)
            }
        }
        u.notice?.let { Small(it.text) }
    }
}

/** M3 Oordeel: model, firmware, klasse en per eis groen/oranje/rood. */
@Composable
fun M3Judgement(u: UiState, vm: HorseSafeViewModel) {
    val st = u.machine
    ScreenFrame(Screen.M3_JUDGEMENT, "Oordeel", bottom = {
        when (st) {
            State.GateNewOk -> Primary("Verder: PIN maken", enabled = !u.busy && !u.env.blocksSecrets) { vm.judgementContinue() }
            is State.GateResumeOk -> Primary("Verder: PIN van papier invoeren", enabled = !u.busy && !u.env.blocksSecrets) { vm.judgementContinue() }
            else -> Unit
        }
        CancelButton(u, vm)
    }) {
        FactsPanel(u)
        if (u.profile == Profile.RECOVERY_YK5 || u.profile == Profile.RECOVERY_BIO) Small(Texts.DIFFERENT_PINS, HsColors.Orange)
        if (st is State.GateResumeOk) {
            Panel {
                SectionTitle("Nog te doen")
                if (st.pending.isEmpty()) Body("Alleen het aantal vingers wordt na de PIN gecontroleerd.")
                st.pending.forEach { Body("• " + pendingText(it)) }
            }
        }
        if (u.env.blocksSecrets) BlockedPanel(u.env.violations.map { "${it.tekst} ${it.advies}" })
        SectionTitle("Eisen")
        CheckList(u.checks)
    }
}

private fun pendingText(w: Written): String = when (w) {
    Written.PIN -> "PIN zetten"
    Written.MIN_PIN_LENGTH_63 -> "Minimum PIN-lengte 63 vastzetten"
    Written.ALWAYS_UV -> "alwaysUv aanzetten"
    Written.FINGERPRINTS -> "Vingers inschrijven"
}

@Composable
internal fun FactsPanel(u: UiState) {
    val f = u.facts ?: return
    Panel {
        SectionTitle(f.aaguidDescription ?: "Onbekend sleuteltype")
        Small("Vormfactor: ${Texts.formFactor(f.formFactor)} · transport: ${f.transport}")
        Small("Firmware: ${f.firmware ?: "onbekend"} (bron: ${f.firmwareSource})")
        Small("Klasse: ${f.keyClass.jsonName ?: "niet toegestaan"} · variant: ${f.variant.name.lowercase()}")
        Small("AAGUID: ${f.aaguid}")
        Small("PIN-pogingen: ${f.pinRetries ?: "?"} · vingerpogingen: ${f.uvRetries ?: "—"}")
        Small(if (f.serialHmac != null) "Serienummer: gelezen (alleen als HMAC bewaard)" else "Serienummer: niet beschikbaar")
    }
}

/** M4 PIN tonen: hold-to-reveal per groep. */
@Composable
fun M4Reveal(u: UiState, vm: HorseSafeViewModel) {
    val allowed = vm.revealAllowed(u)
    ScreenFrame(Screen.M4_REVEAL, "PIN tonen", bottom = {
        Primary("Verder: papier controleren", enabled = u.reveal.seen.size == GroupCheck.GROUPS) { vm.toCopyStep() }
        CancelButton(u, vm)
    }) {
        if (u.env.blocksSecrets) {
            BlockedPanel(u.env.violations.map { "${it.tekst} ${it.advies}" })
            return@ScreenFrame
        }
        Body(Texts.REVEAL_HELP)
        if (!allowed) Small(Texts.REVEAL_BLOCKED, HsColors.Orange)
        MessageBar(u.message) { vm.clearMessage() }
        GroupReveal(
            allowed = allowed,
            pressed = u.reveal.pressed,
            seen = u.reveal.seen,
            onPress = { vm.revealPress(it) },
            onRelease = { vm.revealRelease() },
            draw = { g, drawer -> vm.drawGroup(g, drawer) },
        )
    }
}

/** M5 Overschrijven: papier controleren en bevestigen. */
@Composable
fun M5Copy(u: UiState, vm: HorseSafeViewModel) {
    ScreenFrame(Screen.M5_COPY, "Overschrijven", bottom = {
        Primary("Verder: overtypen", enabled = u.copyConfirmed && !u.busy) { vm.copyDone() }
        Secondary("Terug: groepen nog eens bekijken") { vm.backToReveal() }
        CancelButton(u, vm)
    }) {
        if (u.env.blocksSecrets) {
            BlockedPanel(u.env.violations.map { "${it.tekst} ${it.advies}" })
            return@ScreenFrame
        }
        Body(Texts.COPY_HELP)
        Panel {
            Small("Op het formulier: 9 rijen, elk 7 vakjes voor de tekens en 1 omkaderd vakje voor het controleteken. Gebruik pigmentpen. Geen foto, geen kopie.")
        }
        TickRow(Texts.COPY_CONFIRM, u.copyConfirmed) { vm.setCopyConfirmed(it) }
        Small("Is er al eerder een formulier voor deze sleutel beschreven (een afgebroken poging)? Vernietig dat oude formulier.", HsColors.Orange)
    }
}

/** M6 Overtypen (RETYPE) en M8 PIN invoeren (PAPER), met het eigen toetsenblok. */
@Composable
fun PinEntryScreen(u: UiState, vm: HorseSafeViewModel) {
    val entry = u.entry
    val retype = entry?.mode == EntryMode.RETYPE
    val screen = if (retype) Screen.M6_RETYPE else Screen.M8_PIN_ENTRY
    val practice = u.purpose == Purpose.PRACTICE
    val blocked = u.env.blocksSecrets
    val retriesBlocked = !practice && !retype && vm.pinRetriesBlocked(u)
    val practiceDone = practice && u.practiceKeyResult != null
    ScreenFrame(screen, if (retype) "Overtypen" else if (practice) "Oefenen" else "PIN invoeren", scroll = true, bottom = {
        when {
            practiceDone -> Primary("Afsluiten") { vm.quit() }
            practice -> {
                if (entry?.complete == true) {
                    Primary("Opnieuw oefenen") { vm.practiceAgain() }
                    Secondary("Eén echte controle op de sleutel (optioneel)", enabled = !u.env.blocksSecrets) { vm.practiceOnKey() }
                }
                CancelButton(u, vm)
            }
            retype -> {
                Primary("PIN bevestigen", enabled = entry?.complete == true && !u.busy && !blocked) { vm.entrySubmit() }
                CancelButton(u, vm)
            }
            else -> {
                Primary("PIN gebruiken", enabled = entry?.complete == true && !u.busy && !blocked && !retriesBlocked) { vm.entrySubmit() }
                CancelButton(u, vm)
            }
        }
    }) {
        if (practiceDone) {
            Panel(border = HsColors.Accent) { Body(u.practiceKeyResult ?: "") }
            Small("De echte controle is gedaan. Tik op Afsluiten: de app wist de PIN en sluit af.")
            return@ScreenFrame
        }
        if (blocked) {
            BlockedPanel(u.env.violations.map { "${it.tekst} ${it.advies}" })
            return@ScreenFrame
        }
        if (entry == null) {
            Body("Invoer is gewist (venster verlaten of geblokkeerd). Kom terug op dit scherm om opnieuw te beginnen.")
            return@ScreenFrame
        }
        Body(if (retype) Texts.RETYPE_HELP else Texts.PAPER_HELP)
        if (practice) Small(Texts.PRACTICE_INFO)
        if (!practice && !retype) {
            RetryBanner(vm.pinRetries(u))
            if (u.purpose == Purpose.PIN_CHANGE) Small("Typ de HUIDIGE PIN van het oude papier. De nieuwe PIN staat al klaar.")
        }
        entry.badGroup?.let {
            Body(if (retype) "Groep $it wijkt af. Typ deze groep opnieuw." else "Groep $it klopt niet, controleer het papier.", HsColors.Red)
        }
        u.notice?.let { Small(it.text, HsColors.Orange) }
        MessageBar(u.message) { vm.clearMessage() }
        u.practiceKeyResult?.let { Panel(border = HsColors.Accent) { Body(it) } }
        if (practice && entry.complete) {
            Body("Alle 9 groepen kloppen. Er is niets opgeslagen.", HsColors.Green)
            Small("De echte controle op de sleutel kost een poging als de PIN niet klopt; een juiste PIN zet de teller terug op 8. Daarna sluit de app af.")
        }
        if (entry.complete && !practice) Body("Alle 9 groepen zijn ingevuld.", HsColors.Green)
        GroupDots(entry)
        PinKeypad(
            enabled = !entry.complete && u.windowVisible && !u.busy,
            onKey = { vm.key(it) },
            onDelete = { vm.deleteKey() },
        )
        if (practice) Small(Texts.PRACTICE_ADVICE)
    }
}

/** M6b Onomkeerbaar: rood kader vóór setMinPinLength(63). */
@Composable
fun M6bIrreversible(u: UiState, vm: HorseSafeViewModel) {
    ScreenFrame(Screen.M6B_IRREVERSIBLE, Texts.IRREVERSIBLE_TITLE, bottom = {
        Primary(Texts.IRREVERSIBLE_BUTTON, enabled = u.irreversibleTicked && !u.busy, danger = true) { vm.confirmIrreversible() }
        CancelButton(u, vm)
    }) {
        Panel(border = HsColors.Red, background = HsColors.RedSurface) {
            Text("Minimum PIN-lengte 63 vastzetten", color = HsColors.Red, fontSize = 18.sp)
            Body(Texts.IRREVERSIBLE_TEXT)
            Small("Daarna meldt de sleutel aan de site van HorseSafe dat de PIN minstens 63 tekens is.")
        }
        TickRow(Texts.IRREVERSIBLE_TICK, u.irreversibleTicked) { vm.setIrreversibleTicked(it) }
    }
}

/** M7 Vingers: kiezen, inschrijven met voortgang, testaanraking. */
@Composable
fun M7Fingers(u: UiState, vm: HorseSafeViewModel) {
    val taken = u.fingers.mapNotNull { it.name }.toSet()
    val max = 5
    val range = u.profile?.fingers ?: 2..3
    ScreenFrame(Screen.M7_FINGERS, "Vingers", bottom = {
        Primary("Klaar met vingers", enabled = !u.busy && u.fingers.size in range) { vm.fingersDone() }
        CancelButton(u, vm)
    }) {
        Body("Schrijf ${range.first} of ${range.last} vingers in, verdeeld over beide handen. Na elke vinger volgt een testaanraking.")
        Small("${u.fingers.size} van $max plekken gebruikt.")
        if (u.busy) {
            Panel(border = HsColors.Accent) {
                SectionTitle("Leg je vinger op de sensor")
                val p = u.enrollProgress
                if (p != null) {
                    Body(p.feedback.nl)
                    p.remaining?.let { Small("Nog $it keer.") }
                } else {
                    Body(Texts.TOUCH)
                }
            }
        }
        u.notice?.let { Small(it.text, HsColors.Orange) }
        SectionTitle("Ingeschreven")
        if (u.fingers.isEmpty()) Small("Nog geen vingers.")
        u.fingers.forEach { Body("• ${it.name ?: "(zonder naam)"}") }
        SectionTitle("Kies een vinger")
        Texts.fingerNames.chunked(5).forEach { hand ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                hand.forEach { (name, _) ->
                    androidx.compose.foundation.layout.Box(Modifier.weight(1f)) {
                        androidx.compose.material3.OutlinedButton(
                            onClick = { vm.enrollFinger(name) },
                            enabled = !u.busy && name !in taken && u.fingers.size < range.last,
                        ) { Text(name.substringAfter('-'), fontSize = 11.sp, maxLines = 1) }
                    }
                }
            }
        }
        Small("Bovenste rij: rechterhand. Onderste rij: linkerhand. De naam (bv. R-wijs) gaat zo op de sleutel.")
    }
}

/** Bezig-scherm voor de automatische stappen, met "Opnieuw proberen" na een herstelbare fout. */
@Composable
fun BusyScreen(u: UiState, vm: HorseSafeViewModel) {
    val profile = u.profile ?: Profile.BIO_MAIN
    val order = u.machine?.order ?: 0
    ScreenFrame(Screen.BUSY, "Bezig", bottom = {
        if (!u.busy && u.machine != null && u.machine !is State.Stopped && u.maint == null) {
            Primary("Opnieuw proberen") { vm.retry() }
        }
        CancelButton(u, vm)
    }) {
        if (u.busy) {
            Panel(border = HsColors.Accent) {
                SectionTitle("Bezig met de sleutel")
                Body(Texts.TOUCH)
                Small("Haal de sleutel niet los.")
            }
        }
        u.notice?.let { Body(it.text, HsColors.Orange) }
        if (u.machine != null) StepList(stepsFor(profile, u.pending).map { it.label to it.doneFromOrder }, order)
        if (u.purpose == Purpose.SETUP_RESUME) Small("Hervatten (${SetupMode.RESUME.name.lowercase()}): wat al op de sleutel staat, wordt overgeslagen.")
    }
}
