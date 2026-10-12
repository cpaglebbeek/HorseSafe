package nl.icthorse.horsesafe.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import nl.icthorse.horsesafe.flow.Verdict

object HsColors {
    val Background = Color(0xFF0B0D10)
    val Surface = Color(0xFF161A20)
    val SurfaceHigh = Color(0xFF1F252D)
    val OnSurface = Color(0xFFE8EAED)
    val Muted = Color(0xFF9AA3AD)
    val Accent = Color(0xFF7FB2FF)
    val Green = Color(0xFF3FB950)
    val Orange = Color(0xFFE3A008)
    val Red = Color(0xFFF85149)
    val RedSurface = Color(0xFF3A0D0D)

    fun verdict(v: Verdict): Color = when (v) {
        Verdict.GREEN -> Green
        Verdict.ORANGE -> Orange
        Verdict.RED -> Red
    }
}

private val scheme = darkColorScheme(
    primary = HsColors.Accent,
    onPrimary = Color(0xFF00172F),
    background = HsColors.Background,
    onBackground = HsColors.OnSurface,
    surface = HsColors.Surface,
    onSurface = HsColors.OnSurface,
    surfaceVariant = HsColors.SurfaceHigh,
    onSurfaceVariant = HsColors.Muted,
    error = HsColors.Red,
)

@Composable
fun HorseSafeTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = scheme, content = content)
}
