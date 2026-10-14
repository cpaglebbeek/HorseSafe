package nl.icthorse.horsesafe.biometric

import androidx.biometric.BiometricPrompt
import java.security.Signature
import javax.crypto.Cipher
import nl.icthorse.horsesafe.pairing.Finger
import nl.icthorse.horsesafe.pairing.FingerStep

/** Brug van [StrongGate] naar het koppel-contract [Finger]: altijd met CryptoObject (Cipher of Signature). */
class StrongGateFinger(private val gate: StrongGate) : Finger {
    override suspend fun cipher(cipher: Cipher, step: FingerStep): Cipher =
        gate.authenticate(BiometricPrompt.CryptoObject(cipher), step.title, step.subtitle).cipher
            ?: throw GateException(GateException.Kind.FAILED)

    override suspend fun signature(signature: Signature, step: FingerStep): Signature =
        gate.authenticate(BiometricPrompt.CryptoObject(signature), step.title, step.subtitle).signature
            ?: throw GateException(GateException.Kind.FAILED)
}
