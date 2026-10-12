package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.ctap.BioEnrollment
import com.yubico.yubikit.fido.ctap.FingerprintBioEnrollment
import java.io.IOException
import java.nio.charset.StandardCharsets
import nl.icthorse.horsesafe.yubikey.api.AuthToken
import nl.icthorse.horsesafe.yubikey.api.BioEnrollOps
import nl.icthorse.horsesafe.yubikey.api.EnrollProgress
import nl.icthorse.horsesafe.yubikey.api.Enrollment
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.Permission
import nl.icthorse.horsesafe.yubikey.api.SampleFeedback
import nl.icthorse.horsesafe.yubikey.api.SensorFacts
import nl.icthorse.horsesafe.yubikey.api.TemplateId

/**
 * FingerprintBioEnrollment-adapter (yubikit `FingerprintBioEnrollment(session, protocol, token)`).
 * Elke methode vraagt een [Permission.BE]-token uit deze fase.
 */
internal class YubikitBioEnrollOps(private val phase: YubikitCtapPhase) : BioEnrollOps {

    private fun fpe(token: AuthToken): FingerprintBioEnrollment {
        val raw = phase.unwrap(token, Permission.BE)
        return phase.call {
            if (!BioEnrollment.isSupported(phase.info)) throw KeyError.NotSupported("bioEnroll")
            // Constructor vraagt de modality op en weigert alles behalve vingerafdruk.
            FingerprintBioEnrollment(phase.session, phase.protocol, raw)
        }
    }

    override suspend fun sensorInfo(token: AuthToken): SensorFacts {
        val f = fpe(token)
        return phase.call {
            val s = f.sensorInfo
            SensorFacts(s.fingerprintKind, s.maxCaptureSamplesRequiredForEnroll, s.maxTemplateFriendlyName)
        }
    }

    override suspend fun enumerate(token: AuthToken): List<Enrollment> {
        val f = fpe(token)
        return phase.call {
            // yubikit: lege map bij ERR_INVALID_OPTION (lege Bio).
            f.enumerateEnrollments().entries
                .map { (id, name) -> Enrollment(TemplateId(id), name) }
                .sortedBy { it.templateId.hex }
        }
    }

    override suspend fun enroll(
        token: AuthToken,
        name: String?,
        timeoutMs: Int?,
        onProgress: (EnrollProgress) -> Unit,
    ): TemplateId {
        val f = fpe(token)
        if (name != null) {
            val max = phase.call { f.sensorInfo.maxTemplateFriendlyName }
            require(FingerName.isValid(name, max)) { "vingernaam ongeldig" }
        }
        val ctx = f.enroll(timeoutMs)
        val state = phase.beginCommand()
        var samples = 0
        val templateId: ByteArray = try {
            phase.call {
                var done: ByteArray? = null
                while (done == null) {
                    if (++samples > MAX_SAMPLES) throw KeyError.UserActionTimeout()
                    try {
                        done = ctx.capture(state)
                        onProgress(EnrollProgress(SampleFeedback.GOOD, ctx.remaining))
                    } catch (e: FingerprintBioEnrollment.CaptureError) {
                        // Slechte opname: melden en doorgaan (geen fout).
                        onProgress(EnrollProgress(SampleFeedback.of(e.code), ctx.remaining))
                    }
                }
                done
            }
        } catch (t: Throwable) {
            val cancelledByUs = state.waitForCancel(0)
            // Lopende inschrijving op de sleutel afbreken; best effort (bij een losgekoppelde
            // sleutel lukt dat niet en is het ook niet nodig).
            try {
                ctx.cancel()
            } catch (ignored: IOException) {
            } catch (ignored: CtapException) {
            } catch (ignored: RuntimeException) {
            }
            if (cancelledByUs && t !is KeyError.Disconnected) throw KeyError.Cancelled()
            throw t
        } finally {
            phase.endCommand(state)
        }
        if (name != null) {
            phase.call { f.setName(templateId, name) }
        }
        return TemplateId(templateId)
    }

    override suspend fun rename(token: AuthToken, templateId: TemplateId, name: String) {
        val f = fpe(token)
        val max = phase.call { f.sensorInfo.maxTemplateFriendlyName }
        require(FingerName.isValid(name, max)) { "vingernaam ongeldig" }
        phase.call { f.setName(templateId.bytes(), name) }
    }

    override suspend fun remove(token: AuthToken, templateId: TemplateId) {
        val f = fpe(token)
        phase.call { f.removeEnrollment(templateId.bytes()) }
    }

    companion object {
        /** Bovengrens op het aantal samples per vinger, tegen een eindeloze lus bij steeds CaptureError. */
        const val MAX_SAMPLES = 64
    }
}

/** Regels voor vingernamen (kritiek 15): zichtbare ASCII, niet leeg, lengte in bytes ≤ sensorlimiet. */
object FingerName {
    fun isValid(name: String, maxBytes: Int): Boolean {
        if (name.isBlank() || name.trim() != name) return false
        if (!name.all { it.code in 0x20..0x7E }) return false
        return name.toByteArray(StandardCharsets.US_ASCII).size <= maxBytes
    }
}
