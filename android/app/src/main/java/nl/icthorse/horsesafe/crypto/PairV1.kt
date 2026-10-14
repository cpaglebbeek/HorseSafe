package nl.icthorse.horsesafe.crypto

import java.security.MessageDigest

/**
 * Koppel-afleidingen pair_v1 (HARDWARE_KEYS §13.1; vectoren `specs/testvectors/pair_v1.json`).
 *
 * De telefoon kent het QR-geheim `s` (16 B) en leidt daaruit `k_srv` en `k_web` af; daarmee MAC't hij het
 * transcript twee keer. `s`, `k_srv` en `k_web` zijn geheim: de aanroeper wist ze na de claim.
 */
object PairV1 {
    const val SECRET_LEN = 16

    private const val INFO_SRV = "HSv2 pair srv"
    private const val INFO_WEB = "HSv2 pair web"
    private val ZERO_SALT = ByteArray(32)

    /** Velden van het claim-request, precies als de strings in de JSON. Geen enkel veld bevat "\u0000". */
    data class Fields(
        val pairingId: String,
        val pkC: String,
        val kDevPub: String,
        val kBiosigPub: String,
        val label: String,
        val model: String,
        val appVersion: String,
    ) {
        internal fun ordered(): List<String> = listOf(pairingId, pkC, kDevPub, kBiosigPub, label, model, appVersion)
    }

    fun kSrv(s: ByteArray): ByteArray = Hkdf.sha256(checkSecret(s), ZERO_SALT, INFO_SRV)

    fun kWeb(s: ByteArray): ByteArray = Hkdf.sha256(checkSecret(s), ZERO_SALT, INFO_WEB)

    /** att_challenge = SHA-256("HSv2 pair att" 0x00 pairing_id 0x00 k_srv). */
    fun attChallenge(pairingId: String, kSrv: ByteArray): ByteArray {
        require(kSrv.size == 32) { "k_srv moet 32 bytes zijn" }
        val md = MessageDigest.getInstance("SHA-256")
        md.update("HSv2 pair att".toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(pairingId.toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(kSrv)
        return md.digest()
    }

    /** transcript = UTF-8("HSv2 pair" ‖ "\0" ‖ pairing_id ‖ "\0" ‖ … ‖ app_version). */
    fun transcript(f: Fields): ByteArray {
        val parts = listOf("HSv2 pair") + f.ordered()
        parts.forEach { require(!it.contains('\u0000')) { "transcriptveld bevat een nulteken" } }
        return parts.joinToString("\u0000").toByteArray(Charsets.UTF_8)
    }

    fun mac(key: ByteArray, transcript: ByteArray): ByteArray = Hkdf.hmacSha256(key, transcript)

    /** sas = uint32_be(SHA-256("HSv2 pair sas" 0x00 transcript)[0..4]) mod 10^6, 6 cijfers met voorloopnullen. */
    fun sas(transcript: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("HSv2 pair sas".toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(transcript)
        val d = md.digest()
        val v = ((d[0].toLong() and 0xff) shl 24) or ((d[1].toLong() and 0xff) shl 16) or
            ((d[2].toLong() and 0xff) shl 8) or (d[3].toLong() and 0xff)
        return (v % 1_000_000L).toString().padStart(6, '0')
    }

    private fun checkSecret(s: ByteArray): ByteArray {
        require(s.size == SECRET_LEN) { "QR-geheim moet 16 bytes zijn" }
        return s
    }
}
