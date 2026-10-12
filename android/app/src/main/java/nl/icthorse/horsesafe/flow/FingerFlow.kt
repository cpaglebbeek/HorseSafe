package nl.icthorse.horsesafe.flow

import nl.icthorse.horsesafe.pin.SecretBuffer
import nl.icthorse.horsesafe.report.Report
import nl.icthorse.horsesafe.report.ReportKind
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.EnrollProgress
import nl.icthorse.horsesafe.yubikey.api.Enrollment
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyFacts
import nl.icthorse.horsesafe.yubikey.api.KeyLink
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.TemplateId

/**
 * F6 Vingers beheren, alleen de hoofdsleutel-Bio. [open] met de PIN van papier (M8), daarna per actie
 * een eigen BE-token (eigen CTAP-fase), en na elke actie de lijst opnieuw uitlezen. Maximaal
 * [Limits.MAX_FINGERS] vingers; naam alleen ASCII, ≤ `maxTemplateFriendlyName` bytes (kritiek 15).
 * Nooit Config. De PIN-buffer blijft tot [close] in de flow en wordt daar gewist.
 */
class FingerFlow(
    private val inspector: InspectorOps,
    private val reports: ReportFactory,
    private val env: EnvironmentProbe = EnvironmentProbe.NONE,
    private val enrollTimeoutMs: Int? = null,
    /**
     * Rol van deze sleutel volgens het laatste rapport met dezelfde serial-HMAC, of null (geen rapport).
     * Een noodsleutel-Bio mag in F6 nooit een vinger krijgen (review-bevinding).
     */
    private val knownProfileOf: (serialHmac: String) -> Profile? = { null },
) {
    val profile: Profile = Profile.BIO_MAIN

    private var link: KeyLink? = null
    private var facts: KeyFacts? = null
    private var pin: SecretBuffer? = null
    private var maxNameBytes: Int = Limits.DEFAULT_FRIENDLY_NAME_BYTES
    private var fingers: List<Enrollment> = emptyList()
    private var blocked: Stop? = null

    val current: List<Enrollment> get() = fingers

    /**
     * Alleen de hoofdsleutel (F6): een sleutel die volgens de rapporten de noodsleutel is, of een Bio
     * zonder vinger zonder BIO_MAIN-rapport met dezelfde serial-HMAC, wordt geweigerd vóór er een
     * PIN-poging gebeurt. De VM roept dit ook al vóór M8 aan.
     */
    fun roleStop(f: KeyFacts): Stop? {
        if (f.keyClass != KeyClass.BIO || f.option("bioEnroll") == null) return Stop.CLASS_MISMATCH
        val known = f.serialHmac?.let { s -> runCatching { knownProfileOf(s) }.getOrNull() }
        if (known != null && known != Profile.BIO_MAIN) return Stop.RECOVERY_KEY_NO_FINGERS
        if (f.option("bioEnroll") == false && known != Profile.BIO_MAIN) return Stop.RECOVERY_KEY_NO_FINGERS
        return null
    }

    /** M8 → BE-token → sensorinfo + lijst. De flow neemt [pin] over; bij een fout wordt hij gewist. */
    suspend fun open(link: KeyLink, pin: SecretBuffer): FlowOutcome {
        if (this.pin != null || blocked != null) { pin.wipe(); return FlowOutcome.Blocked(blocked ?: Stop.INTERNAL_ERROR) }
        val r = guarded {
            env.violations().firstOrNull()?.let { return@guarded FlowOutcome.Blocked(it) }
            if (!PinPreflight.syntaxOk(pin)) return@guarded FlowOutcome.SyntaxInvalid
            val f = inspector.inspect(link)
            if (f.keyClass != KeyClass.BIO || f.option("bioEnroll") == null) return@guarded FlowOutcome.Blocked(Stop.CLASS_MISMATCH)
            roleStop(f)?.let { return@guarded FlowOutcome.Blocked(it) }
            PinPreflight.retriesStop(f.pinRetries)?.let { return@guarded FlowOutcome.Blocked(it) }
            val (sensor, list) = link.ctap {
                this.pin.pinToken(pin, Permission.BE).use { t -> bio.sensorInfo(t) to bio.enumerate(t) }
            }
            this.link = link
            this.facts = f
            this.pin = pin
            maxNameBytes = sensor.maxFriendlyNameBytes.takeIf { it > 0 } ?: Limits.DEFAULT_FRIENDLY_NAME_BYTES
            fingers = list
            FlowOutcome.Ready(list, maxNameBytes, f.pinRetries)
        }
        if (r !is FlowOutcome.Ready) {
            pin.wipe()
            if (r is FlowOutcome.Blocked) blocked = r.stop
        }
        return r
    }

    suspend fun add(name: String, onProgress: (EnrollProgress) -> Unit = {}): FlowOutcome = action {
        if (fingers.size >= Limits.MAX_FINGERS) return@action FlowOutcome.Refused("Er staan al ${Limits.MAX_FINGERS} vingers op de sleutel.")
        if (!FingerNames.valid(name, maxNameBytes) || fingers.any { it.name == name }) {
            return@action FlowOutcome.Refused("Ongeldige of dubbele naam (alleen ASCII, maximaal $maxNameBytes tekens).")
        }
        val before = fingers
        val (id, after) = withBe { t ->
            val id = bio.enroll(t, name, enrollTimeoutMs, onProgress)
            id to bio.enumerate(t)
        }
        if (after.size != before.size + 1 || after.none { it.templateId == id }) return@action FlowOutcome.Blocked(Stop.FINGER_COUNT_INVALID)
        fingers = after
        touch()
    }

    suspend fun rename(id: TemplateId, name: String): FlowOutcome = action {
        if (fingers.none { it.templateId == id }) return@action FlowOutcome.Refused("Onbekende vinger.")
        if (!FingerNames.valid(name, maxNameBytes) || fingers.any { it.name == name && it.templateId != id }) {
            return@action FlowOutcome.Refused("Ongeldige of dubbele naam (alleen ASCII, maximaal $maxNameBytes tekens).")
        }
        val after = withBe { t -> bio.rename(t, id, name); bio.enumerate(t) }
        if (after.size != fingers.size || after.none { it.templateId == id && it.name == name }) return@action FlowOutcome.Blocked(Stop.FINGER_COUNT_INVALID)
        fingers = after
        // F6.3: na elke actie de lijst opnieuw uitlezen plus een testaanraking.
        touch()
    }

    /** Laatste vinger alleen met [confirmLast]: "zonder vinger val je terug op de PIN van 63 tekens". */
    suspend fun remove(id: TemplateId, confirmLast: Boolean = false): FlowOutcome = action {
        if (fingers.none { it.templateId == id }) return@action FlowOutcome.Refused("Onbekende vinger.")
        if (fingers.size == 1 && !confirmLast) return@action FlowOutcome.NeedsConfirmLast
        val after = withBe { t -> bio.remove(t, id); bio.enumerate(t) }
        if (after.size != fingers.size - 1 || after.any { it.templateId == id }) return@action FlowOutcome.Blocked(Stop.FINGER_COUNT_INVALID)
        fingers = after
        if (after.isEmpty()) FlowOutcome.Ready(after, maxNameBytes, null) else touch()
    }

    /** Testaanraking: UV-token (MC, wegwerp-rpId) en uvRetries teruglezen. */
    suspend fun testTouch(): FlowOutcome = action { touch() }

    private suspend fun touch(): FlowOutcome {
        val l = link ?: return FlowOutcome.Blocked(Stop.INTERNAL_ERROR)
        return try {
            val left = l.ctap {
                pin.uvToken(Permission.MC, AttestOps.KEURING_RP_ID).use { }
                pin.uvRetries()
            }
            FlowOutcome.Touch(true, left)
        } catch (e: nl.icthorse.horsesafe.yubikey.api.KeyError.UvInvalid) {
            FlowOutcome.Touch(false, e.retriesLeft)
        } catch (e: nl.icthorse.horsesafe.yubikey.api.KeyError.UvBlocked) {
            // CTAP 2.1: een geslaagd PIN-token met permissies zet uvRetries terug op het maximum.
            withBe { }
            FlowOutcome.Retriable(Notice("Vingerpogingen op; met de PIN hersteld. Probeer de testaanraking opnieuw."))
        }
    }

    /** Rapport FINGERS na afloop (verse inspectie) en wissen. */
    suspend fun close(): Report? {
        val l = link
        val out = if (l != null && blocked == null) {
            try {
                val f = inspector.inspect(l)
                val k = KeuringRules.evaluate(f, profile, fingers.size)
                reports.build(ReportKind.FINGERS, profile, f, k.checks, Measured(fingers = fingers, stop = k.stop))
            } catch (e: Throwable) {
                ErrorMap.rethrowIfCancellation(e)
                null
            }
        } else null
        wipeSecrets()
        return out
    }

    fun wipeSecrets() {
        pin?.wipe(); pin = null
    }

    private suspend fun <T> withBe(block: suspend nl.icthorse.horsesafe.yubikey.api.CtapPhase.(nl.icthorse.horsesafe.yubikey.api.AuthToken) -> T): T {
        val l = link ?: throw FlowStop(Stop.INTERNAL_ERROR)
        val p = pin ?: throw FlowStop(Stop.INTERNAL_ERROR)
        return l.ctap { pin.pinToken(p, Permission.BE).use { t -> block(t) } }
    }

    private suspend fun action(block: suspend () -> FlowOutcome): FlowOutcome {
        blocked?.let { return FlowOutcome.Blocked(it) }
        if (pin == null) return FlowOutcome.Blocked(Stop.INTERNAL_ERROR)
        env.violations().firstOrNull()?.let { return FlowOutcome.Blocked(it) }
        val r = guarded(block)
        if (r is FlowOutcome.Blocked) { blocked = r.stop; wipeSecrets() }
        return r
    }
}
