package nl.icthorse.horsesafe.ui.components

import android.graphics.Paint
import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.ui.theme.HsColors

/**
 * Tekent tekens uit een geleende CharArray: (array, start, aantal, deel) met deel 0 = eerste 4 tekens,
 * 1 = laatste 3, 2 = controleteken. De array mag niet bewaard worden.
 */
typealias CharDrawer = (chars: CharArray, start: Int, count: Int, part: Int) -> Unit

/**
 * M4: 9 genummerde kaarten (4 + 3 tekens en een omkaderd controleteken). Een kaart toont zijn inhoud
 * alleen zolang je hem ingedrukt houdt (hold-to-reveal). De glyphs worden op een Canvas getekend
 * met `nativeCanvas.drawText(char[], …)`: geen String, niets in de toegankelijkheidsboom (A-7).
 *
 * @param draw roept de [CharDrawer] aan voor groep `g` (alleen als tonen mag, zie ViewModel).
 */
@Composable
fun GroupReveal(
    allowed: Boolean,
    pressed: Int?,
    seen: Set<Int>,
    onPress: (Int) -> Unit,
    onRelease: () -> Unit,
    draw: (group: Int, CharDrawer) -> Unit,
) {
    val density = LocalDensity.current
    val paint = remember(density) {
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            typeface = Typeface.MONOSPACE
            textSize = with(density) { 26.sp.toPx() }
            color = HsColors.OnSurface.toArgb()
        }
    }
    Column(Modifier.fillMaxWidth().clearAndSetSemantics { }, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        for (row in 0 until 3) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (col in 0 until 3) {
                    val g = row * 3 + col
                    val isPressed = pressed == g && allowed
                    val shape = RoundedCornerShape(10.dp)
                    Box(
                        Modifier
                            .weight(1f)
                            .height(96.dp)
                            .background(if (isPressed) HsColors.SurfaceHigh else HsColors.Surface, shape)
                            .border(1.dp, if (g in seen) HsColors.Green else HsColors.Muted, shape)
                            .pointerInput(g, allowed) {
                                detectTapGestures(onPress = {
                                    if (allowed) {
                                        onPress(g)
                                        try {
                                            tryAwaitRelease()
                                        } finally {
                                            onRelease()
                                        }
                                    }
                                })
                            },
                    ) {
                        Text("${g + 1}", color = HsColors.Muted, fontSize = 13.sp, modifier = Modifier.padding(6.dp))
                        Canvas(Modifier.fillMaxSize().padding(top = 22.dp, start = 6.dp, end = 6.dp, bottom = 6.dp)) {
                            if (!isPressed) {
                                drawRect(HsColors.Muted, topLeft = Offset(0f, size.height / 2 - 1f), size = Size(size.width, 2f))
                                return@Canvas
                            }
                            val charW = paint.measureText("m")
                            val gap = charW * 0.5f
                            val total = charW * 7 + gap + gap + charW * 1.6f
                            val scale = if (total > size.width) size.width / total else 1f
                            val y = size.height / 2 + paint.textSize * 0.35f * scale
                            drawIntoCanvas { canvas ->
                                val nc = canvas.nativeCanvas
                                nc.save()
                                nc.scale(scale, scale, 0f, size.height / 2)
                                val yy = size.height / 2 + paint.textSize * 0.35f
                                draw(g) { chars, start, count, part ->
                                    val x = when (part) {
                                        0 -> 0f
                                        1 -> charW * 4 + gap
                                        else -> charW * 7 + gap * 2 + charW * 0.3f
                                    }
                                    nc.drawText(chars, start, count, x, yy, paint)
                                }
                                nc.restore()
                            }
                            // kader om het controleteken
                            val boxX = (charW * 7 + gap * 2) * scale
                            val boxW = charW * 1.6f * scale
                            drawRect(
                                HsColors.Accent,
                                topLeft = Offset(boxX, y - paint.textSize * 0.95f * scale),
                                size = Size(boxW, paint.textSize * 1.25f * scale),
                                style = Stroke(2f),
                            )
                        }
                    }
                }
            }
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Small("Bekeken: ${seen.size} van ${GroupCheck.GROUPS} groepen.")
        }
    }
}
