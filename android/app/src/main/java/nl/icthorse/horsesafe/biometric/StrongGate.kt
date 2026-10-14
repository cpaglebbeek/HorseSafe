package nl.icthorse.horsesafe.biometric

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/** Uitkomst van `canAuthenticate(BIOMETRIC_STRONG)` in eigen termen (voor het blokkerende scherm). */
enum class BioAvailability { OK, NONE_ENROLLED, NO_HARDWARE, UNAVAILABLE, UPDATE_REQUIRED, UNSUPPORTED }

/** Waarom een vingerprompt niet slaagde. Geen platformtekst: die kan details bevatten die we niet tonen. */
class GateException(val kind: Kind) : Exception(kind.name) {
    enum class Kind { CANCELLED, LOCKOUT, NOT_AVAILABLE, NOT_BIOMETRIC, FAILED }
}

/**
 * De enige toegang tot de vingerafdruk (HARDWARE_KEYS §7.2, E1/E2):
 * - alleen `BIOMETRIC_STRONG`; nooit een toestel-PIN, patroon of wachtwoord als alternatief;
 * - altijd met een `CryptoObject` (de Keystore-sleutel heeft timeout 0, dus de vinger ontgrendelt precies
 *   deze ene bewerking);
 * - negatieve knop "Annuleren".
 *
 * Bronbeleid (`PairingSourcePolicyTest`): `BiometricPrompt` staat alleen in dit pakket en elke
 * `authenticate(`-aanroep heeft een CryptoObject.
 */
class StrongGate(
    private val appContext: Context,
    private val activity: () -> FragmentActivity?,
) {
    fun availability(): BioAvailability = when (BiometricManager.from(appContext).canAuthenticate(BIOMETRIC_STRONG)) {
        BiometricManager.BIOMETRIC_SUCCESS -> BioAvailability.OK
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BioAvailability.NONE_ENROLLED
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BioAvailability.NO_HARDWARE
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BioAvailability.UNAVAILABLE
        BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BioAvailability.UPDATE_REQUIRED
        else -> BioAvailability.UNSUPPORTED
    }

    /**
     * Toont de systeemprompt en geeft na een geldige vinger het (nu ontgrendelde) [crypto] terug.
     * @throws GateException bij annuleren, lockout of een andere fout.
     */
    suspend fun authenticate(crypto: BiometricPrompt.CryptoObject, title: String, subtitle: String): BiometricPrompt.CryptoObject =
        withContext(Dispatchers.Main) {
            val act = activity() ?: throw GateException(GateException.Kind.NOT_AVAILABLE)
            if (availability() != BioAvailability.OK) throw GateException(GateException.Kind.NOT_AVAILABLE)
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText(NEGATIVE)
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .setConfirmationRequired(true)
                .build()
            suspendCancellableCoroutine { cont ->
                val prompt = BiometricPrompt(
                    act,
                    ContextCompat.getMainExecutor(act),
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (!cont.isActive) return
                            val out = result.cryptoObject
                            when {
                                result.authenticationType != BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC ->
                                    cont.resumeWithException(GateException(GateException.Kind.NOT_BIOMETRIC))
                                out == null -> cont.resumeWithException(GateException(GateException.Kind.FAILED))
                                else -> cont.resume(out)
                            }
                        }

                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (!cont.isActive) return
                            val kind = when (errorCode) {
                                BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_CANCELED ->
                                    GateException.Kind.CANCELLED
                                BiometricPrompt.ERROR_LOCKOUT, BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> GateException.Kind.LOCKOUT
                                BiometricPrompt.ERROR_NO_BIOMETRICS, BiometricPrompt.ERROR_HW_NOT_PRESENT, BiometricPrompt.ERROR_HW_UNAVAILABLE ->
                                    GateException.Kind.NOT_AVAILABLE
                                else -> GateException.Kind.FAILED
                            }
                            cont.resumeWithException(GateException(kind))
                        }

                        // onAuthenticationFailed: vinger niet herkend; de prompt blijft open voor een nieuwe poging.
                    },
                )
                cont.invokeOnCancellation { prompt.cancelAuthentication() }
                prompt.authenticate(info, crypto)
            }
        }

    companion object {
        const val NEGATIVE = "Annuleren"
    }
}
