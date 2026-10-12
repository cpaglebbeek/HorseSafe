package nl.icthorse.horsesafe.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import nl.icthorse.horsesafe.ui.HorseSafeViewModel
import nl.icthorse.horsesafe.ui.Screen
import nl.icthorse.horsesafe.ui.Texts
import nl.icthorse.horsesafe.ui.UiState
import nl.icthorse.horsesafe.ui.components.Body
import nl.icthorse.horsesafe.ui.components.MessageBar
import nl.icthorse.horsesafe.ui.components.Panel
import nl.icthorse.horsesafe.ui.components.Primary
import nl.icthorse.horsesafe.ui.components.ScreenFrame
import nl.icthorse.horsesafe.ui.components.SectionTitle
import nl.icthorse.horsesafe.ui.components.Secondary
import nl.icthorse.horsesafe.ui.components.Small
import nl.icthorse.horsesafe.ui.theme.HsColors

/**
 * M7 in beheermodus (F6, alleen de hoofdsleutel-Bio): toevoegen (max 5), hernoemen (namen uit de vaste
 * lijst, ASCII), verwijderen (extra bevestiging bij de laatste vinger) en een testaanraking.
 * Nooit setMinPinLength of alwaysUv.
 */
@Composable
fun M7FingersManage(u: UiState, vm: HorseSafeViewModel) {
    val taken = u.fingers.mapNotNull { it.name }.toSet()
    val max = 5
    val renameFor = u.renameFor
    ScreenFrame(Screen.M7_FINGERS, "Vingers beheren", bottom = {
        Primary("Klaar", enabled = !u.busy) { vm.fingersDone() }
        CancelButton(u, vm)
    }) {
        MessageBar(u.message) { vm.clearMessage() }
        Small("${u.fingers.size} van $max plekken gebruikt · namen maximaal ${u.maxNameBytes} tekens (ASCII).")
        if (u.busy) {
            Panel(border = HsColors.Accent) {
                SectionTitle("Bezig met de sleutel")
                val p = u.enrollProgress
                if (p != null) {
                    Body(p.feedback.nl)
                    p.remaining?.let { Small("Nog $it keer.") }
                } else {
                    Body(Texts.TOUCH)
                }
            }
        }
        SectionTitle("Op de sleutel")
        if (u.fingers.isEmpty()) Body("Geen vingers. Zonder vinger val je terug op de PIN van 63 tekens.", HsColors.Orange)
        u.fingers.forEach { f ->
            Panel {
                Body(f.name ?: "(zonder naam)")
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Box(Modifier.weight(1f)) { Secondary("Hernoemen", enabled = !u.busy) { vm.fingerAskRename(if (renameFor == f.templateId) null else f.templateId) } }
                    Box(Modifier.weight(1f)) {
                        Secondary(if (u.confirmLast == f.templateId) "Ja, verwijderen" else "Verwijderen", enabled = !u.busy) { vm.fingerRemove(f.templateId) }
                    }
                }
                if (renameFor == f.templateId) NameGrid(taken, enabled = !u.busy) { name -> vm.fingerRename(f.templateId, name) }
            }
        }
        Secondary("Testaanraking", enabled = !u.busy && u.fingers.isNotEmpty()) { vm.fingerTouch() }
        if (u.fingers.size < max) {
            SectionTitle("Vinger toevoegen")
            NameGrid(taken, enabled = !u.busy && renameFor == null) { name -> vm.enrollFinger(name) }
            Small("Bovenste rij: rechterhand. Onderste rij: linkerhand.")
        }
    }
}

@Composable
private fun NameGrid(taken: Set<String>, enabled: Boolean, onPick: (String) -> Unit) {
    Texts.fingerNames.chunked(5).forEach { hand ->
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            hand.forEach { (name, _) ->
                Box(Modifier.weight(1f)) {
                    OutlinedButton(onClick = { onPick(name) }, enabled = enabled && name !in taken) {
                        Text(name.substringAfter('-'), fontSize = 11.sp, maxLines = 1)
                    }
                }
            }
        }
    }
}
