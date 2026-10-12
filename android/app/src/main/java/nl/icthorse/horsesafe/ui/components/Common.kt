package nl.icthorse.horsesafe.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Verdict
import nl.icthorse.horsesafe.ui.Screen
import nl.icthorse.horsesafe.ui.theme.HsColors

/** Vaste schermopbouw: kop met schermcode, scrollbare inhoud, knoppen onderaan. */
@Composable
fun ScreenFrame(
    screen: Screen,
    title: String,
    scroll: Boolean = true,
    bottom: (@Composable ColumnScope.() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(Modifier.fillMaxSize().background(HsColors.Background).padding(horizontal = 16.dp, vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(screen.code, color = HsColors.Muted, fontSize = 13.sp)
            Spacer(Modifier.size(8.dp))
            Text(title, color = HsColors.OnSurface, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(12.dp))
        val body = Modifier.weight(1f).fillMaxWidth()
        Column(if (scroll) body.verticalScroll(rememberScrollState()) else body, verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
        if (bottom != null) {
            Spacer(Modifier.height(8.dp))
            Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp), content = bottom)
        }
    }
}

@Composable
fun Body(text: String, color: Color = HsColors.OnSurface) {
    Text(text, color = color, fontSize = 15.sp, lineHeight = 21.sp)
}

@Composable
fun Small(text: String, color: Color = HsColors.Muted) {
    Text(text, color = color, fontSize = 13.sp, lineHeight = 18.sp)
}

@Composable
fun SectionTitle(text: String) {
    Text(text, color = HsColors.OnSurface, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
}

@Composable
fun Panel(modifier: Modifier = Modifier, border: Color? = null, background: Color = HsColors.Surface, content: @Composable ColumnScope.() -> Unit) {
    val shape = RoundedCornerShape(10.dp)
    var m = modifier.fillMaxWidth().background(background, shape)
    if (border != null) m = m.border(2.dp, border, shape)
    Column(m.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp), content = content)
}

@Composable
fun VerdictDot(v: Verdict) {
    Box(Modifier.size(12.dp).background(HsColors.verdict(v), CircleShape))
}

@Composable
fun CheckLine(c: CheckResult) {
    Row(verticalAlignment = Alignment.Top) {
        Box(Modifier.padding(top = 4.dp)) { VerdictDot(c.verdict) }
        Spacer(Modifier.size(8.dp))
        Column {
            Text(c.detail, color = HsColors.OnSurface, fontSize = 14.sp, lineHeight = 19.sp)
            Text(c.id, color = HsColors.Muted, fontSize = 11.sp)
        }
    }
}

@Composable
fun CheckList(checks: List<CheckResult>) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) { checks.forEach { CheckLine(it) } }
}

@Composable
fun Primary(text: String, enabled: Boolean = true, danger: Boolean = false, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(52.dp),
        colors = if (danger) ButtonDefaults.buttonColors(containerColor = HsColors.Red, contentColor = Color.White) else ButtonDefaults.buttonColors(),
    ) { Text(text, fontSize = 16.sp) }
}

@Composable
fun Secondary(text: String, enabled: Boolean = true, onClick: () -> Unit) {
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().height(48.dp)) { Text(text) }
}

@Composable
fun TickRow(text: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(enabled = enabled) { onChange(!checked) }.padding(vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = if (enabled) onChange else null, enabled = enabled)
        Spacer(Modifier.size(4.dp))
        Text(text, color = HsColors.OnSurface, fontSize = 15.sp, lineHeight = 20.sp)
    }
}

/** Menukaart voor M0. */
@Composable
fun MenuCard(title: String, subtitle: String?, enabled: Boolean = true, onClick: () -> Unit) {
    Panel(Modifier.clickable(enabled = enabled, onClick = onClick), background = if (enabled) HsColors.SurfaceHigh else HsColors.Surface) {
        Text(title, color = if (enabled) HsColors.OnSurface else HsColors.Muted, fontSize = 16.sp, fontWeight = FontWeight.Medium)
        if (subtitle != null) Small(subtitle)
    }
}

@Composable
fun MessageBar(text: String?, onClose: () -> Unit) {
    if (text == null) return
    Panel(Modifier.clickable(onClick = onClose), background = HsColors.SurfaceHigh) {
        Body(text)
        Small("Tik om te sluiten.")
    }
}

@Composable
fun BlockedPanel(lines: List<String>) {
    Panel(border = HsColors.Red, background = HsColors.RedSurface) {
        SectionTitle("Geblokkeerd")
        lines.forEach { Body(it) }
    }
}
