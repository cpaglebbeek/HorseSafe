package nl.icthorse.horsesafe.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import nl.icthorse.horsesafe.pairing.QrScanner
import nl.icthorse.horsesafe.ui.PairStep
import nl.icthorse.horsesafe.ui.PairingUi
import nl.icthorse.horsesafe.ui.PairingViewModel
import nl.icthorse.horsesafe.ui.Texts
import nl.icthorse.horsesafe.ui.components.Body
import nl.icthorse.horsesafe.ui.components.BlockedPanel
import nl.icthorse.horsesafe.ui.components.MessageBar
import nl.icthorse.horsesafe.ui.components.Panel
import nl.icthorse.horsesafe.ui.components.Primary
import nl.icthorse.horsesafe.ui.components.ScreenFrame
import nl.icthorse.horsesafe.ui.components.SectionTitle
import nl.icthorse.horsesafe.ui.components.Secondary
import nl.icthorse.horsesafe.ui.components.Small
import nl.icthorse.horsesafe.ui.theme.HsColors

/**
 * Schermen M14-M19 "Telefoon koppelen" (deel 2, HARDWARE_KEYS §13.3). [onExit] = terug naar M0.
 * Geen geheimen in beeld: alleen de SAS (6 cijfers, niet geheim), het toestellabel en de sleutelnamen.
 */
@Composable
fun PairingRoot(vm: PairingViewModel, onExit: () -> Unit) {
    val u by vm.ui.collectAsState()
    val exit = {
        vm.leave()
        onExit()
    }
    BackHandler {
        when (u.step) {
            PairStep.SCAN, PairStep.WORKING -> vm.cancel()
            else -> exit()
        }
    }
    when (u.step) {
        PairStep.INTRO, PairStep.WORKING -> M14Pair(u, vm, exit)
        PairStep.SCAN -> M15Scan(u, vm)
        PairStep.SAS -> M16Sas(u, vm, exit)
        PairStep.DONE -> M17Paired(u, vm, exit)
        PairStep.BIO_BLOCKED -> M18BioRequired(u, vm, exit)
        PairStep.REPAIR -> M19Repair(vm, exit)
    }
}

@Composable
private fun M14Pair(u: PairingUi, vm: PairingViewModel, exit: () -> Unit) {
    val context = LocalContext.current
    val permission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) vm.startScan() else vm.cameraDenied()
    }
    val scan = {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) vm.startScan()
        else permission.launch(Manifest.permission.CAMERA)
    }
    val working = u.step == PairStep.WORKING
    ScreenFrame(
        u.step.screen,
        "Telefoon koppelen",
        bottom = {
            when {
                working -> Secondary("Afbreken") { vm.cancel() }
                u.confirmReplace -> {
                    Primary("Ja, koppeling vervangen", danger = true) { scan() }
                    Secondary("Nee, terug") { vm.cancelReplace() }
                }
                else -> {
                    Primary("QR-code scannen") { scan() }
                    Secondary("Terug") { exit() }
                }
            }
        },
    ) {
        if (u.error != null) BlockedPanel(listOf(u.error))
        if (working) {
            Panel {
                SectionTitle(u.working ?: "Bezig…")
                Body(Texts.PAIR_TWO_TOUCHES)
            }
            return@ScreenFrame
        }
        if (u.confirmReplace) {
            Panel(border = HsColors.Red) {
                SectionTitle("Deze telefoon is al gekoppeld")
                Body(Texts.PAIR_REPLACE)
            }
        }
        Body(Texts.PAIR_INTRO)
        Panel {
            SectionTitle("Zo gaat het")
            Texts.PAIR_STEPS.forEachIndexed { i, s -> Body("${i + 1}. $s") }
        }
        Small(Texts.PAIR_NETWORK)
    }
}

@Composable
private fun M15Scan(u: PairingUi, vm: PairingViewModel) {
    ScreenFrame(u.step.screen, "QR-code scannen", scroll = false, bottom = { Secondary("Afbreken") { vm.cancel() } }) {
        Body("Richt de camera op de QR-code op het scherm van de laptop.")
        QrScanner(Modifier.fillMaxWidth().aspectRatio(1f)) { vm.onQr(it) }
        MessageBar(u.message) { vm.clearMessage() }
        Small("De code is 5 minuten geldig en werkt één keer. Er wordt geen foto bewaard.")
    }
}

@Composable
private fun M16Sas(u: PairingUi, vm: PairingViewModel, exit: () -> Unit) {
    ScreenFrame(u.step.screen, "Vergelijk de code", bottom = { Secondary("Sluiten (koppeling blijft open)") { exit() } }) {
        if (u.error != null) BlockedPanel(listOf(u.error))
        Panel {
            SectionTitle("Vergelijk met je laptop")
            Text(
                Texts.sasGrouped(u.sas ?: "------"),
                color = HsColors.OnSurface,
                fontSize = 44.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
            )
        }
        Body(Texts.PAIR_SAS_HELP)
        Small(if (u.error == null) "Wachten op de laptop… (tot 10 minuten)" else "Niet meer aan het wachten.")
        if (u.error != null) Secondary("Opnieuw wachten") { vm.open() }
        Secondary("Koppeling op deze telefoon afbreken") { vm.abandon() }
    }
}

@Composable
private fun M17Paired(u: PairingUi, vm: PairingViewModel, exit: () -> Unit) {
    ScreenFrame(u.step.screen, "Gekoppeld", bottom = { Secondary("Terug naar start") { exit() } }) {
        MessageBar(u.message) { vm.clearMessage() }
        if (u.error != null) BlockedPanel(listOf(u.error))
        Panel(border = HsColors.Green) {
            SectionTitle(u.label ?: "Deze telefoon")
            Body("Deze telefoon is gekoppeld. Vraagt een vertrouwde browser om je kluis te openen, dan verschijnt hier een verzoek zolang de app open is.")
        }
        if (u.keys.isEmpty()) {
            Small("De server meldt (nog) geen kluis voor deze telefoon.")
        } else {
            SectionTitle("Verzegelde kopieën")
            u.keys.forEach { k ->
                Panel {
                    Body(k.label)
                    Small("Kluis ${k.vaultId.take(8)}…")
                    Secondary("Proef: kopie openen", enabled = u.working == null) { vm.trial(k) }
                    if (u.trialFor == k.keyId && u.trialResult != null) Body(u.trialResult, HsColors.Green)
                }
            }
            Small(Texts.PAIR_TRIAL_INFO)
        }
        if (u.working != null) Small(u.working)
        Secondary("Status verversen") { vm.refresh() }
        Secondary("Opnieuw koppelen (vervangt deze koppeling)") { vm.startScan() }
    }
}

@Composable
private fun M18BioRequired(u: PairingUi, vm: PairingViewModel, exit: () -> Unit) {
    ScreenFrame(
        u.step.screen,
        "Vingerafdruk nodig",
        bottom = {
            Primary("Opnieuw controleren") { vm.recheck() }
            Secondary("Terug") { exit() }
        },
    ) {
        BlockedPanel(listOf(Texts.bioBlocked(u.bio)))
        Body(Texts.PAIR_BIO_RULE)
    }
}

@Composable
private fun M19Repair(vm: PairingViewModel, exit: () -> Unit) {
    ScreenFrame(
        nl.icthorse.horsesafe.ui.Screen.M19_REPAIR,
        "Opnieuw koppelen",
        bottom = {
            Primary("Opnieuw koppelen") { vm.restart() }
            Secondary("Terug naar start") { exit() }
        },
    ) {
        BlockedPanel(listOf(Texts.PAIR_REPAIR))
        Body(Texts.PAIR_REPAIR_LAPTOP)
    }
}
