package nl.icthorse.horsesafe.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import nl.icthorse.horsesafe.ui.theme.HsColors

/** Stappen met status: klaar (groen), nu bezig (accent), nog te doen (grijs). */
@Composable
fun StepList(steps: List<Pair<String, Int>>, currentOrder: Int) {
    var currentMarked = false
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        steps.forEach { (label, doneFrom) ->
            val done = currentOrder >= doneFrom
            val now = !done && !currentMarked
            if (now) currentMarked = true
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(12.dp).background(
                        when {
                            done -> HsColors.Green
                            now -> HsColors.Accent
                            else -> HsColors.Surface
                        },
                        CircleShape,
                    ),
                )
                Spacer(Modifier.size(8.dp))
                Text(
                    label,
                    color = if (done || now) HsColors.OnSurface else HsColors.Muted,
                    fontSize = 15.sp,
                    fontWeight = if (now) FontWeight.SemiBold else FontWeight.Normal,
                )
            }
        }
    }
}

/** "PIN-pogingen x/8"; bij 3 of minder rood en geblokkeerd. */
@Composable
fun RetryBanner(retries: Int?, max: Int = 8) {
    val blocked = retries == null || retries <= 3
    Panel(border = if (blocked) HsColors.Red else HsColors.Muted) {
        Text(
            "PIN-pogingen ${retries ?: "?"}/$max",
            color = if (blocked) HsColors.Red else HsColors.OnSurface,
            fontSize = 16.sp,
            fontWeight = FontWeight.SemiBold,
        )
        if (blocked) Small("Geblokkeerd: nog 3 of minder pogingen (of onbekend). Controleer eerst het papier met \"Oefenen\" en steek de sleutel opnieuw in.")
        else Small("Elke foute PIN kost een poging op de sleutel. Een fout controleteken niet.")
    }
}
