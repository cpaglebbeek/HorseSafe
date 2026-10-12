package nl.icthorse.horsesafe.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import nl.icthorse.horsesafe.pin.Alphabet
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.ui.EntryMode
import nl.icthorse.horsesafe.ui.EntryUi
import nl.icthorse.horsesafe.ui.theme.HsColors

/**
 * Eigen toetsenblok (A-6): raster 6 × 5 met de 29 tekens van het alfabet en "Wis". Geen systeem-IME,
 * geen TextField, geen klembord, geen selectie. De hele toetsenblok-boom is onzichtbaar voor
 * toegankelijkheidsdiensten (`clearAndSetSemantics`, A-7).
 *
 * Hardwaretoetsenbord (A-6): `clickable` is in non-touch mode focusbaar en reageert dan op Enter,
 * DpadCenter en Space. Daarom krijgt elke toets `focusProperties { canFocus = false }` en slikt het
 * blok elke sleutelgebeurtenis (`onPreviewKeyEvent { true }`). Daarnaast slikt `MainActivity` op de
 * schermen met een geheim alle toetsen behalve Terug en volume (ook een YubiKey 5 met OTP typt als
 * toetsenbord).
 */
@Composable
fun PinKeypad(enabled: Boolean, onKey: (Char) -> Unit, onDelete: () -> Unit, modifier: Modifier = Modifier) {
    val keys: List<Char?> = Alphabet.CHARS.toList() + listOf(null) // null = Wis
    Column(modifier.fillMaxWidth().onPreviewKeyEvent { true }.clearAndSetSemantics { }, verticalArrangement = Arrangement.spacedBy(6.dp)) {
        keys.chunked(COLUMNS).forEach { row ->
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                row.forEach { k ->
                    val shape = RoundedCornerShape(8.dp)
                    Box(
                        Modifier
                            .weight(1f)
                            .height(48.dp)
                            .background(if (enabled) HsColors.SurfaceHigh else HsColors.Surface, shape)
                            .focusProperties { canFocus = false }
                            .clickable(enabled = enabled) { if (k == null) onDelete() else onKey(k) },
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = if (k == null) "Wis" else k.toString(),
                            color = if (enabled) HsColors.OnSurface else HsColors.Muted,
                            fontSize = if (k == null) 14.sp else 20.sp,
                        )
                    }
                }
                repeat(COLUMNS - row.size) { Box(Modifier.weight(1f)) }
            }
        }
    }
}

private const val COLUMNS = 6

/**
 * Voortgang van de invoer als bolletjes: per groep 7 (en bij M8 een omkaderd vakje voor het
 * controleteken). Toont nooit tekens. Groen = groep klopt, rood kader = laatst afgekeurde groep.
 */
@Composable
fun GroupDots(entry: EntryUi, modifier: Modifier = Modifier) {
    Column(modifier.fillMaxWidth().clearAndSetSemantics { }, verticalArrangement = Arrangement.spacedBy(4.dp)) {
        for (g in 0 until GroupCheck.GROUPS) {
            val done = g < entry.groupsDone
            val current = g == entry.groupsDone
            val bad = entry.badGroup == g + 1
            val border = when {
                bad -> HsColors.Red
                current -> HsColors.Accent
                else -> Color.Transparent
            }
            Row(
                Modifier.fillMaxWidth().border(1.dp, border, RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("${g + 1}", color = HsColors.Muted, fontSize = 13.sp, modifier = Modifier.padding(end = 8.dp))
                val filled = when {
                    done -> GroupCheck.GROUP_SIZE
                    current -> entry.typedInGroup
                    else -> 0
                }
                Canvas(Modifier.weight(1f).height(16.dp)) {
                    val n = GroupCheck.GROUP_SIZE + if (entry.mode == EntryMode.PAPER) 1 else 0
                    val step = size.width / n
                    for (i in 0 until n) {
                        val c = Offset(step * i + step / 2, size.height / 2)
                        val isCheck = entry.mode == EntryMode.PAPER && i == GroupCheck.GROUP_SIZE
                        val on = if (isCheck) done else i < filled
                        val color = when {
                            done && entry.groupCheckAvailable -> HsColors.Green
                            on -> HsColors.OnSurface
                            else -> HsColors.Muted
                        }
                        if (isCheck) {
                            drawRect(color, topLeft = Offset(c.x - 7f, c.y - 7f), size = androidx.compose.ui.geometry.Size(14f, 14f), style = if (on) androidx.compose.ui.graphics.drawscope.Fill else Stroke(2f))
                        } else if (on) {
                            drawCircle(color, radius = 6f, center = c)
                        } else {
                            drawCircle(color, radius = 6f, center = c, style = Stroke(2f))
                        }
                    }
                }
                val label = when {
                    bad -> "wijkt af"
                    done && entry.groupCheckAvailable -> "klopt"
                    done -> "ingevuld"
                    current && entry.awaitingCheck -> "controleteken"
                    else -> ""
                }
                Text(label, color = if (bad) HsColors.Red else HsColors.Muted, fontSize = 12.sp, modifier = Modifier.padding(start = 8.dp))
            }
        }
    }
}
