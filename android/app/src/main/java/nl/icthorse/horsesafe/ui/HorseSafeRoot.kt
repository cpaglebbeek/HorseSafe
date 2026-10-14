package nl.icthorse.horsesafe.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import nl.icthorse.horsesafe.ui.screens.BusyScreen
import nl.icthorse.horsesafe.ui.screens.M0Start
import nl.icthorse.horsesafe.ui.screens.M10Report
import nl.icthorse.horsesafe.ui.screens.M11Stop
import nl.icthorse.horsesafe.ui.screens.M12About
import nl.icthorse.horsesafe.ui.screens.M13Reset
import nl.icthorse.horsesafe.ui.screens.M1Checklist
import nl.icthorse.horsesafe.ui.screens.M2Connect
import nl.icthorse.horsesafe.ui.screens.M3Judgement
import nl.icthorse.horsesafe.ui.screens.M4Reveal
import nl.icthorse.horsesafe.ui.screens.M5Copy
import nl.icthorse.horsesafe.ui.screens.M6bIrreversible
import nl.icthorse.horsesafe.ui.screens.M7Fingers
import nl.icthorse.horsesafe.ui.screens.M7FingersManage
import nl.icthorse.horsesafe.ui.screens.M9Keuring
import nl.icthorse.horsesafe.ui.screens.PairingRoot
import nl.icthorse.horsesafe.ui.screens.PinEntryScreen
import nl.icthorse.horsesafe.ui.theme.HorseSafeTheme
import nl.icthorse.horsesafe.ui.theme.HsColors

/** Activity-acties die de UI nodig heeft (opslagkiezer). */
class RootActions(
    val export: () -> Unit,
    val import: () -> Unit,
)

/** Wortel van de Compose-UI: kiest het scherm uit [UiState.screen]. */
@Composable
fun HorseSafeRoot(vm: HorseSafeViewModel, pairing: PairingViewModel, services: AppServices, signerSha256: String?, actions: RootActions) {
    val u by vm.ui.collectAsState()
    HorseSafeTheme {
        Box(Modifier.fillMaxSize().background(HsColors.Background).safeDrawingPadding()) {
            // Terug-knop: vóór een geheim naar start; daarna niets (alleen Afbreken/Afsluiten in beeld).
            BackHandler(enabled = u.screen != Screen.M0_START || u.pickProfileFor != null) {
                if (u.pickProfileFor != null) vm.pickProfile(null) else vm.backToStart()
            }
            when (u.screen) {
                Screen.M0_START -> M0Start(u, vm, services.appVersion) {
                    vm.openPairing()
                    pairing.open()
                }
                Screen.M1_CHECKLIST -> M1Checklist(u, vm)
                Screen.M2_CONNECT -> M2Connect(u, vm)
                Screen.M3_JUDGEMENT -> M3Judgement(u, vm)
                Screen.M4_REVEAL -> M4Reveal(u, vm)
                Screen.M5_COPY -> M5Copy(u, vm)
                Screen.M6_RETYPE, Screen.M8_PIN_ENTRY -> PinEntryScreen(u, vm)
                Screen.M6B_IRREVERSIBLE -> M6bIrreversible(u, vm)
                Screen.M7_FINGERS -> if (u.purpose == Purpose.FINGERS) M7FingersManage(u, vm) else M7Fingers(u, vm)
                Screen.M9_KEURING -> M9Keuring(u, vm, actions.export)
                Screen.M10_REPORT -> M10Report(u, vm, actions.export, actions.import)
                Screen.M11_STOP -> M11Stop(u, vm)
                Screen.M12_ABOUT -> M12About(vm, services.appVersion, services.trust, signerSha256, services.isDebugBuild)
                Screen.M13_RESET -> M13Reset(u, vm)
                Screen.M14_PAIR, Screen.M15_PAIR_SCAN, Screen.M16_PAIR_SAS, Screen.M17_PAIRED, Screen.M18_BIO_REQUIRED, Screen.M19_REPAIR ->
                    PairingRoot(pairing) { vm.backToStart() }
                Screen.BUSY -> BusyScreen(u, vm)
            }
        }
    }
}
