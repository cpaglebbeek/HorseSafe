package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.PinCompare
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.Permission

/**
 * F5 PIN wijzigen. Volgorde: [begin] (sleutel ingericht, pogingen > 3) → [generateNewPin] (M4) →
 * [confirmRetyped] (M5, alle 9 groepen) → [submit] met de huidige PIN van papier (M8).
 *
 * - Syntaxcontrole van de huidige PIN vóór de poging (63 tekens uit het alfabet); een fout kost geen poging.
 * - Bij ≤ 3 pogingen geblokkeerd, ook vlak vóór de poging (verse telling).
 * - Teruglezen: 8 pogingen, geen forcePinChange, minimum 63 (ruw 0x0D) en een CM-token met de NIEUWE PIN.
 * - Nooit Config (setMinPinLength/toggleAlwaysUv).
 * Alle buffers worden na afloop gewist; "Afsluiten" beëindigt daarna het proces (A-12).
 */
class ChangePinFlow(
    val profile: Profile,
    private val inspector: InspectorOps,
    private val reports: ReportFactory,
    private val generator: PinGenerator = PinGenerator(),
    private val env: EnvironmentProbe = EnvironmentProbe.NONE,
    private val maxPinPolicy: MaxPinLengthPolicy = MaxPinLengthPolicy.STOP,
) {
    private var link: KeyLink? = null
    private var facts: KeyFacts? = null
    private var newA: SecretBuffer? = null
    private var newB: SecretBuffer? = null
    private var finished = false

    suspend fun begin(link: KeyLink): FlowOutcome = guarded {
        if (finished) return@guarded FlowOutcome.Blocked(Stop.INTERNAL_ERROR)
        val f = inspector.inspect(link)
        this.link = link
        this.facts = f
        val det = DetectionPolicy.evaluate(f, profile, maxPinPolicy)
        det.stop?.let { return@guarded block(it) }
        PinPreflight.retriesStop(f.pinRetries)?.let { return@guarded block(it) }
        // Alleen een volledig ingerichte sleutel (minimum 63 staat al, PIN aanwezig).
        val k = KeuringRules.evaluate(f, profile)
        val relevant = k.checks.filter { it.verdict == Verdict.RED && it.id in setOf("k_client_pin", "k_min_pin_length", "k_force_pin_change") }
        if (relevant.isNotEmpty()) return@guarded block(k.stop ?: Stop.PIN_READBACK_FAILED)
        FlowOutcome.Done(null, null, f.pinRetries)
    }

    /** M4: nieuwe PIN maken. false = omgeving niet in orde of niet begonnen. */
    fun generateNewPin(): Boolean {
        if (facts == null || finished || newA != null || newB != null) return false
        if (env.violations().isNotEmpty()) return false
        newA = generator.generate()
        return true
    }

    fun <T> revealNewPin(block: (SecretBuffer) -> T): T? = newA?.let(block)

    fun retypedGroupMatches(group: Int, typed: CharArray): Boolean {
        val a = newA ?: return false
        if (group !in 0 until GroupCheck.GROUPS) return false
        val tmp = CharArray(GroupCheck.GROUP_SIZE)
        return try {
            a.useChars { c -> System.arraycopy(c, group * GroupCheck.GROUP_SIZE, tmp, 0, GroupCheck.GROUP_SIZE) }
            PinCompare.equal(tmp, typed)
        } finally {
            tmp.fill('\u0000')
        }
    }

    /** M5: hertypte nieuwe PIN. De flow neemt [retyped] over (of wist hem bij een verschil). */
    fun confirmRetyped(retyped: SecretBuffer): Boolean {
        val a = newA
        if (a == null || !PinGenerator.isWellFormed(retyped) || !PinCompare.equal(a, retyped)) {
            retyped.wipe()
            return false
        }
        a.wipe(); newA = null
        newB = retyped
        return true
    }

    /** M8: huidige PIN; wordt altijd gewist. */
    suspend fun submit(current: SecretBuffer): FlowOutcome = try {
        val r = guarded {
            val l = link ?: return@guarded FlowOutcome.Blocked(Stop.INTERNAL_ERROR)
            val nb = newB ?: return@guarded FlowOutcome.Blocked(Stop.INTERNAL_ERROR)
            env.violations().firstOrNull()?.let { return@guarded block(it) }
            if (!PinPreflight.syntaxOk(current)) return@guarded FlowOutcome.SyntaxInvalid
            val retries = l.ctap { pin.pinRetries() }.count
            PinPreflight.retriesStop(retries)?.let { return@guarded block(it) }
            val info = try {
                l.ctap {
                    pin.changePin(current, nb)
                    freshInfo()
                }
            } catch (e: KeyError.PinPolicyViolation) {
                return@guarded block(if (facts?.pinComplexity == true) Stop.PIN_POLICY_COMPLEXITY else Stop.PIN_POLICY_MPE_PIV)
            }
            if (info.pinRetries != Limits.FULL_PIN_RETRIES || info.forcePinChange) return@guarded block(Stop.PIN_READBACK_FAILED)
            val raw = l.readRawInfo()
            if (!raw.present.minPinLength0x0D || raw.minPinLength != Limits.PIN_LENGTH) return@guarded block(Stop.MIN_PIN_LENGTH_READBACK_FAILED)
            // Nieuwe PIN werkt (CM-token, geen bijwerking).
            l.ctap { pin.pinToken(nb, Permission.CM).use { } }
            val after = inspector.inspect(l)
            val k = KeuringRules.evaluate(after, profile)
            val report = reports.build(ReportKind.PIN_CHANGE, profile, after, k.checks, Measured(stop = k.stop))
            FlowOutcome.Done(report, k.stop, after.pinRetries)
        }
        if (r is FlowOutcome.Done || r is FlowOutcome.Blocked) finish()
        r
    } finally {
        current.wipe()
    }

    private fun block(s: Stop): FlowOutcome {
        finish()
        return FlowOutcome.Blocked(s)
    }

    private fun finish() {
        finished = true
        wipeSecrets()
    }

    fun wipeSecrets() {
        newA?.wipe(); newA = null
        newB?.wipe(); newB = null
    }
}
