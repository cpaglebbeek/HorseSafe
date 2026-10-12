package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.yubikey.api.TemplateId
import java.security.MessageDigest

/** SHA-256-hulpjes voor rapportvelden (kleine-letter hex). */
object ReportHashes {
    fun sha256Hex(bytes: ByteArray): String = SerialHasher.hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    /** `Report.fingerTemplateHashes`: SHA-256 van de ruwe template-id. */
    fun templateHash(id: TemplateId): String = sha256Hex(id.bytes())

    /** `Report.attestationLeafSha256`: SHA-256 van het DER-leafcertificaat. */
    fun leafHash(derCertificate: ByteArray): String = sha256Hex(derCertificate)
}
