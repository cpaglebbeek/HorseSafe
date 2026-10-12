package nl.icthorse.horsesafe.attest

import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

/** De vertrouwensankers zijn onleesbaar of wijken af van de verwachte SHA-256 (fail-closed). */
class TrustRootsException(message: String) : Exception(message)

/**
 * Vertrouwensankers voor de attestation-keten, gemaakt uit de bytes van `yubico_fido_roots.pem`.
 *
 * `attest/` leest zelf geen bestanden (A-16, kritiek 17): de app-laag leest `assets/trust/yubico_fido_roots.pem`
 * en geeft de bytes plus `BuildConfig.TRUST_ROOTS_SHA256` door aan [fromPem]. Tests injecteren hier een
 * eigen test-CA.
 *
 * Indeling zoals de server (pyOpenSSL `X509Store` zonder partial-chain): alleen zelf-ondertekende
 * certificaten zijn [anchors]; de overige (Yubico's FIDO-intermediates) zijn [intermediates] en mogen
 * alleen helpen een pad naar een anchor te bouwen.
 */
class TrustRoots private constructor(
    val anchors: List<TrustAnchor>,
    val intermediates: List<X509Certificate>,
    /** SHA-256 (kleine-letter-hex) van de PEM-bytes, voor M12. Leeg bij [EMPTY]. */
    val sha256Hex: String,
) {
    val isEmpty: Boolean get() = anchors.isEmpty()

    override fun toString(): String = "TrustRoots(anchors=${anchors.size}, intermediates=${intermediates.size})"

    companion object {
        /** Geen ankers: elke verificatie faalt (fail-closed). */
        val EMPTY = TrustRoots(emptyList(), emptyList(), "")

        /**
         * @param pem een of meer PEM-certificaten achter elkaar.
         * @param expectedSha256Hex als niet null: de SHA-256 van [pem] moet hieraan gelijk zijn.
         * @throws TrustRootsException bij een afwijkende hash, een parsefout of als er geen zelf-ondertekend
         *   certificaat in zit.
         */
        fun fromPem(pem: ByteArray, expectedSha256Hex: String? = null): TrustRoots {
            val hash = sha256Hex(pem)
            if (expectedSha256Hex != null && !MessageDigest.isEqual(
                    hash.toByteArray(Charsets.US_ASCII),
                    expectedSha256Hex.lowercase().toByteArray(Charsets.US_ASCII),
                )
            ) {
                throw TrustRootsException("SHA-256 van de vertrouwensankers wijkt af")
            }
            val certs = try {
                CertificateFactory.getInstance("X.509")
                    .generateCertificates(pem.inputStream())
                    .map { it as? X509Certificate ?: throw TrustRootsException("geen X.509-certificaat") }
            } catch (e: CertificateException) {
                throw TrustRootsException("vertrouwensankers niet leesbaar")
            }
            if (certs.isEmpty()) throw TrustRootsException("geen certificaten in de vertrouwensankers")
            val (selfSigned, others) = certs.partition { isSelfSigned(it) }
            if (selfSigned.isEmpty()) throw TrustRootsException("geen zelf-ondertekende root in de vertrouwensankers")
            return TrustRoots(selfSigned.map { TrustAnchor(it, null) }, others, hash)
        }

        internal fun isSelfSigned(c: X509Certificate): Boolean {
            if (c.subjectX500Principal != c.issuerX500Principal) return false
            return try {
                c.verify(c.publicKey)
                true
            } catch (e: Exception) {
                false
            }
        }

        internal fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    }
}
