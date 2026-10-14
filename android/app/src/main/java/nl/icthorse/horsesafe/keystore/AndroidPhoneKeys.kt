package nl.icthorse.horsesafe.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.UnrecoverableKeyException
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore-implementatie van [PhoneKeys], precies volgens §13.2:
 *
 * | Sleutel  | Eigenschappen |
 * |----------|---------------|
 * | K_dev    | EC P-256 sign, geen UV, unlockedDeviceRequired, attestation met att_challenge, StrongBox eerst |
 * | K_biosig | EC P-256 sign, UV per gebruik (timeout 0, alleen biometrie STRONG), invalidated-by-enrollment, attestation met att_challenge, StrongBox eerst |
 * | K_wrap   | AES-256-GCM, zelfde UV-eisen als K_biosig + unlockedDeviceRequired |
 *
 * StrongBox eerst; bij StrongBoxUnavailableException of een andere ProviderException tijdens de generatie
 * met StrongBox terugval op de TEE ([StrongBoxFallback]). Een sleutel die alleen in software staat wordt
 * geweigerd ([KeystoreUnavailableException]); de server controleert het niveau ook.
 *
 * Twee sleutelsets ([KeySlot] A en B): een nieuwe koppeling maakt haar sleutels in de set die NIET in gebruik
 * is, zodat een mislukte claim de bestaande koppeling niet raakt (§13.3 stap 5). Welke set actief is, staat
 * in het koppelbestand (`pairing/DeviceStore`).
 */
class AndroidPhoneKeys : PhoneKeys {

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun create(attChallenge: ByteArray, slot: KeySlot): PhoneKeyMaterial {
        require(attChallenge.size == 32) { "att_challenge moet 32 bytes zijn" }
        delete(slot) // alleen deze set; de andere (bestaande koppeling) blijft staan
        val a = Aliases.of(slot)
        try {
            val devLevel = generateEc(a.dev, attChallenge, biometric = false)
            val bioLevel = generateEc(a.biosig, attChallenge, biometric = true)
            val wrapLevel = generateWrap(a.wrap)
            val ks = keyStore()
            val devChain = ks.getCertificateChain(a.dev)?.map { it.encoded } ?: throw KeystoreUnavailableException("geen attestatieketen (K_dev)")
            val bioChain = ks.getCertificateChain(a.biosig)?.map { it.encoded } ?: throw KeystoreUnavailableException("geen attestatieketen (K_biosig)")
            if (devChain.size < 2 || bioChain.size < 2) throw KeystoreUnavailableException("attestatieketen te kort")
            val devSpki = ks.getCertificate(a.dev).publicKey.encoded
            val bioSpki = ks.getCertificate(a.biosig).publicKey.encoded
            listOf(devLevel, bioLevel, wrapLevel).forEach {
                if (it == KeyLevel.SOFTWARE) throw KeystoreUnavailableException("sleutel niet in beveiligde hardware")
            }
            return PhoneKeyMaterial(devSpki, bioSpki, devChain, bioChain, devLevel, bioLevel, wrapLevel)
        } catch (e: KeystoreUnavailableException) {
            delete(slot)
            throw e
        } catch (e: GeneralSecurityException) {
            delete(slot)
            throw KeystoreUnavailableException("sleutels maken mislukt")
        } catch (e: ProviderException) {
            delete(slot)
            throw KeystoreUnavailableException("sleutels maken mislukt")
        }
    }

    private fun generateEc(alias: String, challenge: ByteArray, biometric: Boolean): KeyLevel {
        fun spec(strongBox: Boolean): KeyGenParameterSpec {
            val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .setIsStrongBoxBacked(strongBox)
            if (biometric) {
                b.setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
            } else {
                b.setUnlockedDeviceRequired(true)
            }
            return b.build()
        }
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val pair = StrongBoxFallback.generate { strongBox ->
            kpg.initialize(spec(strongBox))
            kpg.generateKeyPair()
        }
        return levelOf(pair.private)
    }

    private fun generateWrap(alias: String): KeyLevel {
        fun spec(strongBox: Boolean): KeyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .build()
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val key = StrongBoxFallback.generate { strongBox ->
            kg.init(spec(strongBox))
            kg.generateKey()
        }
        val info = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return level(info)
    }

    private fun levelOf(key: PrivateKey): KeyLevel {
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        return level(info)
    }

    private fun level(info: KeyInfo): KeyLevel = when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyLevel.STRONGBOX
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyLevel.TEE
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeyLevel.SOFTWARE
        else -> KeyLevel.UNKNOWN
    }

    override fun wrapCipher(slot: KeySlot): Cipher = guard {
        val key = keyStore().getKey(Aliases.of(slot).wrap, null) as? SecretKey ?: throw KeysInvalidatedException()
        Cipher.getInstance(AES_GCM).apply { init(Cipher.ENCRYPT_MODE, key) }
    }

    override fun unwrapCipher(slot: KeySlot, iv: ByteArray): Cipher = guard {
        val key = keyStore().getKey(Aliases.of(slot).wrap, null) as? SecretKey ?: throw KeysInvalidatedException()
        Cipher.getInstance(AES_GCM).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
    }

    override fun biosigSignature(slot: KeySlot): Signature = guard {
        val key = keyStore().getKey(Aliases.of(slot).biosig, null) as? PrivateKey ?: throw KeysInvalidatedException()
        Signature.getInstance(SIG_ALG).apply { initSign(key) }
    }

    override fun signDev(slot: KeySlot, message: ByteArray): ByteArray = guard {
        val key = keyStore().getKey(Aliases.of(slot).dev, null) as? PrivateKey ?: throw KeysInvalidatedException()
        Signature.getInstance(SIG_ALG).run {
            initSign(key)
            update(message)
            sign()
        }
    }

    override fun present(slot: KeySlot): Boolean = try {
        val ks = keyStore()
        Aliases.of(slot).all.all { ks.containsAlias(it) }
    } catch (e: GeneralSecurityException) {
        false
    } catch (e: java.io.IOException) {
        false
    }

    override fun deleteAll() = KeySlot.entries.forEach(::delete)

    override fun delete(slot: KeySlot) {
        try {
            val ks = keyStore()
            Aliases.of(slot).all.forEach { a ->
                try {
                    if (ks.containsAlias(a)) ks.deleteEntry(a)
                } catch (e: GeneralSecurityException) {
                    // best effort; geen details wegschrijven
                }
            }
        } catch (e: GeneralSecurityException) {
            // Keystore niet bereikbaar: niets te wissen
        } catch (e: java.io.IOException) {
            // idem
        }
    }

    /**
     * KeyPermanentlyInvalidatedException (vingerafdrukken gewijzigd) en een verdwenen sleutel →
     * [KeysInvalidatedException]; de aanroeper wist alles lokaal.
     */
    private inline fun <T> guard(block: () -> T): T = try {
        block()
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeysInvalidatedException()
    } catch (e: UnrecoverableKeyException) {
        throw KeysInvalidatedException()
    } catch (e: InvalidKeyException) {
        throw KeystoreUnavailableException("sleutel niet bruikbaar")
    }

    /** Keystore-aliassen per set. Set A houdt de oorspronkelijke namen. */
    private class Aliases(val dev: String, val biosig: String, val wrap: String) {
        val all get() = listOf(dev, biosig, wrap)

        companion object {
            private val A = Aliases("horsesafe_k_dev", "horsesafe_k_biosig", "horsesafe_k_wrap")
            private val B = Aliases("horsesafe_k_dev_b", "horsesafe_k_biosig_b", "horsesafe_k_wrap_b")
            fun of(slot: KeySlot) = when (slot) {
                KeySlot.A -> A
                KeySlot.B -> B
            }
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val AES_GCM = "AES/GCM/NoPadding"
        const val SIG_ALG = "SHA256withECDSA"
    }
}
