package nl.icthorse.horsesafe.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.ui.HorseSafeViewModel
import nl.icthorse.horsesafe.ui.KeyPresence
import nl.icthorse.horsesafe.ui.ResetStep
import nl.icthorse.horsesafe.ui.Screen
import nl.icthorse.horsesafe.ui.Texts
import nl.icthorse.horsesafe.ui.UiState
import nl.icthorse.horsesafe.ui.components.BlockedPanel
import nl.icthorse.horsesafe.ui.components.Body
import nl.icthorse.horsesafe.ui.components.MessageBar
import nl.icthorse.horsesafe.ui.components.Panel
import nl.icthorse.horsesafe.ui.components.Primary
import nl.icthorse.horsesafe.ui.components.ScreenFrame
import nl.icthorse.horsesafe.ui.components.SectionTitle
import nl.icthorse.horsesafe.ui.components.Secondary
import nl.icthorse.horsesafe.ui.components.Small
import nl.icthorse.horsesafe.ui.theme.HsColors
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.Transport

/**
 * M13 Sleutel wissen (F8, 0.3.1): aansluiten → zien wat er gewist wordt → laatste 4 cijfers van het
 * serienummer overtypen → 3 s ingedrukt houden → opnieuw insteken → aanraken → nagelezen.
 */
@Composable
fun M13Reset(u: UiState, vm: HorseSafeViewModel) {
    val r = u.reset ?: return
    ScreenFrame(Screen.M13_RESET, "Sleutel wissen", bottom = {
        when (r.step) {
            ResetStep.DONE -> {
                Primary("Inrichten als hoofdsleutel (Bio)", enabled = u.facts?.keyClass == KeyClass.BIO) { vm.setupAfterReset(Profile.BIO_MAIN) }
                Secondary("Inrichten als noodsleutel") {
                    vm.setupAfterReset(if (u.facts?.keyClass == KeyClass.BIO) Profile.RECOVERY_BIO else Profile.RECOVERY_YK5)
                }
                Secondary("Terug naar start") { vm.backToStart() }
            }
            else -> Secondary("Stoppen, niets wissen", enabled = !u.busy && r.step != ResetStep.WIPING) { vm.backToStart() }
        }
    }) {
        MessageBar(u.message) { vm.clearMessage() }
        r.notice?.let {
            Panel(border = HsColors.Orange) { Body(it) }
        }
        when (r.step) {
            ResetStep.CONNECT -> {
                Panel(border = HsColors.Red, background = HsColors.RedSurface) {
                    SectionTitle("Let op: wissen is onomkeerbaar")
                    Body(Texts.RESET_WARNING)
                }
                Body(Texts.RESET_CONNECT)
                Panel {
                    when {
                        u.busy -> Body("Sleutel gevonden; bezig met uitlezen…")
                        u.key == KeyPresence.MULTIPLE -> Body("Er is meer dan één sleutel aangesloten. Haal ze allemaal los en sluit er één aan.", HsColors.Red)
                        else -> Body("Wacht op een YubiKey…")
                    }
                }
            }
            ResetStep.CONFIRM -> {
                FactsPanel(u)
                u.facts?.let { f ->
                    Panel {
                        SectionTitle("Nu op de sleutel")
                        Body("PIN: " + if (f.option("clientPin") == true) "ja" else "nee")
                        if (f.keyClass == KeyClass.BIO) Body("Vingers: " + if (f.option("bioEnroll") == true) "ja" else "nee")
                        Body("Minimale PIN-lengte: ${f.minPinLength} · alwaysUv: " + if (f.option("alwaysUv") == true) "aan" else "uit")
                    }
                }
                Panel(border = HsColors.Red, background = HsColors.RedSurface) {
                    SectionTitle("Dit gaat verloren")
                    Body(Texts.RESET_LOSES)
                }
                if (u.env.blocksSecrets) {
                    BlockedPanel(u.env.violations.map { "${it.tekst} ${it.advies}" })
                    return@ScreenFrame
                }
                SectionTitle("Bevestig met het serienummer")
                Body("Typ de laatste 4 cijfers van het serienummer: ${r.serialLast4 ?: "?"}. Ze staan ook op de achterkant van de sleutel; controleer dat het de sleutel in je hand is.")
                Body("Ingetypt: " + r.typed.padEnd(4, '·'), if (r.typedOk) HsColors.Green else HsColors.OnSurface)
                if (r.typedWrong) Small("Die cijfers kloppen niet. Probeer opnieuw.", HsColors.Red)
                if (!r.typedOk) {
                    DigitKeypad(onDigit = { vm.resetDigit(it) }, onDelete = { vm.resetDeleteDigit() })
                } else {
                    HoldToConfirm("Houd 3 seconden ingedrukt om te wissen", enabled = !u.busy) { vm.resetHoldComplete() }
                }
            }
            ResetStep.REPLUG -> {
                val nfc = u.facts?.transport == Transport.NFC
                Panel(border = HsColors.Accent) {
                    SectionTitle("Nu opnieuw aansluiten")
                    Body(if (nfc) Texts.RESET_REPLUG_NFC else Texts.RESET_REPLUG_USB)
                }
                Small(Texts.RESET_WINDOW)
            }
            ResetStep.WIPING -> {
                Panel(border = HsColors.Accent) {
                    SectionTitle("Raak de sleutel aan")
                    Body(if (u.facts?.keyClass == KeyClass.BIO) Texts.RESET_TOUCH_BIO else Texts.RESET_TOUCH)
                }
                Small("Niet loskoppelen tot de app klaar meldt.")
            }
            ResetStep.DONE -> {
                Panel(border = HsColors.Green) {
                    SectionTitle("Gewist")
                    Body(Texts.RESET_DONE)
                }
                FactsPanel(u)
                Small(Texts.RESET_DONE_SERVER)
            }
        }
    }
}

/** Cijfertoetsen 0-9 en "Wis" (geen systeemtoetsenbord, zoals PinKeypad). */
@Composable
private fun DigitKeypad(onDigit: (Char) -> Unit, onDelete: () -> Unit) {
    val keys: List<Char?> = "1234567890".toList() + listOf(null)
    Column(Modifier.fillMaxWidth().onPreviewKeyEvent { true }, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        keys.chunked(4).forEach { row ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                row.forEach { k ->
                    Box(
                        Modifier.weight(1f).height(48.dp)
                            .background(HsColors.SurfaceHigh, RoundedCornerShape(8.dp))
                            .focusProperties { canFocus = false }
                            .clickable { if (k == null) onDelete() else onDigit(k) },
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(if (k == null) "Wis" else k.toString(), color = HsColors.OnSurface, fontSize = if (k == null) 14.sp else 20.sp)
                    }
                }
                repeat(4 - row.size) { Box(Modifier.weight(1f)) }
            }
        }
    }
}

/** Knop die pas na [HOLD_MS] onafgebroken indrukken [onComplete] aanroept; loslaten = opnieuw. */
@Composable
private fun HoldToConfirm(label: String, enabled: Boolean, onComplete: () -> Unit) {
    var progress by remember { mutableFloatStateOf(0f) }
    val scope = rememberCoroutineScope()
    val shape = RoundedCornerShape(10.dp)
    Box(
        Modifier.fillMaxWidth().height(64.dp).clip(shape).background(HsColors.RedSurface, shape)
            .pointerInput(enabled) {
                detectTapGestures(onPress = {
                    if (!enabled) return@detectTapGestures
                    val job = scope.launch {
                        val steps = 30
                        for (i in 1..steps) {
                            delay(HOLD_MS / steps)
                            progress = i / steps.toFloat()
                        }
                        onComplete()
                    }
                    tryAwaitRelease()
                    job.cancel()
                    progress = 0f
                })
            },
        contentAlignment = Alignment.CenterStart,
    ) {
        Box(Modifier.fillMaxHeight().fillMaxWidth(progress).background(HsColors.Red, shape))
        Text(label, color = HsColors.OnSurface, fontSize = 16.sp, modifier = Modifier.fillMaxWidth(), textAlign = androidx.compose.ui.text.style.TextAlign.Center)
    }
}

private const val HOLD_MS = 3000L
