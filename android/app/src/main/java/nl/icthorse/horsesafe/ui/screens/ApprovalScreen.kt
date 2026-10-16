package nl.icthorse.horsesafe.ui.screens

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import nl.icthorse.horsesafe.approval.ApprovalCard
import nl.icthorse.horsesafe.approval.CardTrust
import nl.icthorse.horsesafe.ui.ApprovalUi
import nl.icthorse.horsesafe.ui.ApprovalViewModel
import nl.icthorse.horsesafe.ui.Screen
import nl.icthorse.horsesafe.ui.components.BlockedPanel
import nl.icthorse.horsesafe.ui.components.Body
import nl.icthorse.horsesafe.ui.components.Panel
import nl.icthorse.horsesafe.ui.components.Primary
import nl.icthorse.horsesafe.ui.components.ScreenFrame
import nl.icthorse.horsesafe.ui.components.SectionTitle
import nl.icthorse.horsesafe.ui.components.Secondary
import nl.icthorse.horsesafe.ui.components.Small
import nl.icthorse.horsesafe.ui.theme.HsColors

/** Is er iets van de goedkeuring te tonen (kaart of afsluitende melding)? */
fun ApprovalUi.visible(): Boolean = card != null || result != null

/**
 * M20 "Ontgrendelverzoek" (HARDWARE_KEYS §11.3.5, §14.9): browsernaam, kluis, IP, UA en tijd; knoppen
 * **Goedkeuren (vinger)**, **Weigeren**, **Weigeren en browser intrekken**. Geen geheimen in beeld.
 */
@Composable
fun ApprovalScreen(u: ApprovalUi, vm: ApprovalViewModel) {
    BackHandler { vm.dismiss() }
    val card = u.card
    if (card == null) {
        ScreenFrame(Screen.M20_APPROVAL, "Ontgrendelverzoek", bottom = { Primary("Sluiten") { vm.dismiss() } }) {
            val text = u.result ?: ""
            if (u.resultOk) {
                Panel(border = HsColors.Green) { Body(text) }
            } else {
                BlockedPanel(listOf(text))
            }
        }
        return
    }
    val busy = u.working != null
    ScreenFrame(
        Screen.M20_APPROVAL,
        "Ontgrendelverzoek",
        bottom = {
            if (card.canApprove) Primary("Goedkeuren (vinger)", enabled = !busy) { vm.approve() }
            if (card.trust != CardTrust.SIG_INVALID || !card.autoDenied) {
                Secondary("Weigeren", enabled = !busy) { vm.deny(revoke = false) }
                Primary("Weigeren en browser intrekken", enabled = !busy, danger = true) { vm.deny(revoke = true) }
            }
            Secondary("Sluiten", enabled = !busy) { vm.dismiss() }
        },
    ) {
        TrustPanel(card)
        Panel(border = if (card.canApprove) null else HsColors.Red) {
            SectionTitle(card.browserLabel)
            Small(if (card.canApprove) "Naam van de vertrouwde browser; het koppelbewijs wordt na je vinger gecontroleerd." else "Naam van de browser (niet gecontroleerd).")
            Body("Kluis: " + (card.vaultLabel ?: card.request.vaultId.take(8) + "…"))
            Body("IP-adres: " + (card.request.ip ?: "onbekend"))
            Body("Browser: " + (card.request.ua?.take(160) ?: "onbekend"))
            Body("Tijd: " + time(card.request.requestedAt ?: card.request.createdAt))
        }
        Small("Verwacht je dit verzoek niet? Weiger het. Ontgrendelen kan alleen met je vingerafdruk, nooit met een toestel-PIN.")
        if (u.working != null) Small(u.working)
        if (u.error != null) BlockedPanel(listOf(u.error))
    }
}

@Composable
private fun TrustPanel(card: ApprovalCard) {
    when (card.trust) {
        CardTrust.SIGNED -> Body("Een vertrouwde browser vraagt om je kluis te openen.")
        CardTrust.SIG_INVALID -> BlockedPanel(
            listOf(
                ApprovalViewModel.UNTRUSTED,
                if (card.autoDenied) "De handtekening van de browser klopt niet. Het verzoek is automatisch geweigerd."
                else "De handtekening van de browser klopt niet. Weigeren lukte nog niet; weiger het verzoek hieronder.",
            ),
        )
        CardTrust.LABEL_INVALID -> BlockedPanel(listOf(ApprovalViewModel.UNTRUSTED, "De browsernaam bevat ongeldige tekens. Weiger dit verzoek."))
        CardTrust.EXPIRED -> BlockedPanel(listOf("Dit verzoek is verlopen. Vraag op de laptop opnieuw om te ontgrendelen."))
        CardTrust.NO_COPY -> BlockedPanel(listOf("Deze telefoon heeft geen kopie voor deze kluis. Goedkeuren kan hier niet."))
    }
}

private fun time(unixSeconds: Long): String =
    SimpleDateFormat("d MMM yyyy HH:mm:ss", Locale.forLanguageTag("nl-NL")).format(Date(unixSeconds * 1000))
