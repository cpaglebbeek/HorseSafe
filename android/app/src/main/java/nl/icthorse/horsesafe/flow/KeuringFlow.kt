package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.report.Report
import nl.icthorse.horsesafe.report.ReportCompare
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.Permission

/**
 * F4 Keuren. (a) zonder PIN: alleen lezen. (b) met PIN: per doel een eigen token (CM metadata, BE
 * vingerlijst, MC keuring). Beide vergelijken met het vorige rapport; elk verschil is rood, geen vorig
 * rapport is oranje (kritiek 9). Een andere AAGUID of serienummer-HMAC dan het vorige rapport = [Stop.KEY_SWAPPED].
 * Keuren schrijft niets op de sleutel behalve de wegwerp-credential (rk=false) bij (b).
 */
class KeuringFlow(
    private val inspector: InspectorOps,
    private val judge: AttestationJudge,
    private val reports: ReportFactory,
    private val env: EnvironmentProbe = EnvironmentProbe.NONE,
    private val maxPinPolicy: MaxPinLengthPolicy = MaxPinLengthPolicy.STOP,
) {
    /** Regels die de keuring zelf scherper beoordeelt dan de detectie. */
    private val detectionOnlyIds = setOf("client_pin", "always_uv")

    suspend fun withoutPin(link: KeyLink, profile: Profile, previous: Report?): FlowOutcome = guarded {
        val facts = inspector.inspect(link)
        conclude(ReportKind.KEURING_ZONDER_PIN, profile, facts, previous, null, Measured())
    }

    /** [pin] wordt altijd gewist. */
    suspend fun withPin(link: KeyLink, profile: Profile, pin: SecretBuffer, previous: Report?): FlowOutcome = try {
        guarded {
            env.violations().firstOrNull()?.let { return@guarded FlowOutcome.Blocked(it) }
            if (!PinPreflight.syntaxOk(pin)) return@guarded FlowOutcome.SyntaxInvalid
            val before = inspector.inspect(link)
            PinPreflight.retriesStop(before.pinRetries)?.let { return@guarded FlowOutcome.Blocked(it) }
            val bio = before.keyClass == KeyClass.BIO
            val (meta, fingers, evidence) = link.ctap {
                val m = this.pin.pinToken(pin, Permission.CM).use { credMgmt.metadata(it) }
                val f = if (bio) this.pin.pinToken(pin, Permission.BE).use { this.bio.enumerate(it) } else null
                val ev = this.pin.pinToken(pin, Permission.MC, AttestOps.KEURING_RP_ID).use { attest.keuringCredential(it) }
                Triple(m, f, ev)
            }
            val outcome = if (evidence.withToken && evidence.rpId == AttestOps.KEURING_RP_ID) {
                judge.judge(evidence, AttestExpectation(before.aaguid, before.keyClass, requireUv = true, rpId = AttestOps.KEURING_RP_ID))
            } else AttestOutcome.Failed(Stop.ATTEST_RP_ID_HASH)
            val after = inspector.inspect(link)
            val attCheck = when (outcome) {
                is AttestOutcome.Ok -> CheckResult("attestation", Verdict.GREEN, "Echtheid aangetoond (Yubico-certificaat).")
                is AttestOutcome.Failed -> CheckResult("attestation", Verdict.RED, outcome.stop.tekst)
            }
            conclude(
                ReportKind.KEURING_MET_PIN, profile, after, previous,
                (outcome as? AttestOutcome.Failed)?.stop,
                Measured(
                    residentCredentials = meta.existingResidentCredentials,
                    fingers = fingers,
                    attestationOk = outcome is AttestOutcome.Ok,
                    attestationLeafSha256 = (outcome as? AttestOutcome.Ok)?.leafSha256,
                ),
                listOf(attCheck),
            )
        }
    } finally {
        pin.wipe()
    }

    private fun conclude(
        kind: ReportKind,
        profile: Profile,
        facts: KeyFacts,
        previous: Report?,
        attestStop: Stop?,
        m: Measured,
        extra: List<CheckResult> = emptyList(),
    ): FlowOutcome {
        val det = DetectionPolicy.evaluate(facts, profile, maxPinPolicy)
        val k = KeuringRules.evaluate(facts, profile, m.fingers?.size)
        val checks = det.checks.filterNot { it.id in detectionOnlyIds } + k.checks + extra
        val draft = reports.build(kind, profile, facts, checks, m)
        // Alleen een basis van vóór dit rapport (een geïmporteerd rapport uit de toekomst telt niet).
        val compared = ReportCompare.apply(draft, previous?.takeIf { it.profile == profile && it.createdAt <= draft.createdAt })
        val swapped = compared.differences.any { it == "aaguid" || it == "serialHmac" || it == "keyClass" }
        val stop = when {
            swapped -> Stop.KEY_SWAPPED
            else -> attestStop ?: det.stop ?: k.stop
        }
        val report = compared.copy(stop = stop?.name)
        return FlowOutcome.Done(report, stop, facts.pinRetries)
    }
}
