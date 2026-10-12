package nl.icthorse.horsesafe.flow.fake

import java.security.MessageDigest
import java.time.Instant
import nl.icthorse.horsesafe.flow.AttestExpectation
import nl.icthorse.horsesafe.flow.AttestOutcome
import nl.icthorse.horsesafe.flow.AttestationJudge
import nl.icthorse.horsesafe.flow.ReportFactory
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.report.RawSerialKey
import nl.icthorse.horsesafe.report.ReportHashes
import nl.icthorse.horsesafe.yubikey.AaguidEntry
import nl.icthorse.horsesafe.yubikey.AaguidLookup
import nl.icthorse.horsesafe.yubikey.Inspector
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.AttestationEvidence
import nl.icthorse.horsesafe.yubikey.api.Firmware
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyFormFactor
import nl.icthorse.horsesafe.yubikey.api.KeyVariant
import nl.icthorse.horsesafe.report.SerialHasher as ReportSerialHasher

/** Testprofielen (plan §Tests 2). */
object KeyProfiles {
    val BIO_FIDO = Aaguid("d8522d9f-575b-4866-88a9-ba99fa02f35b")
    val BIO_MPE = Aaguid("7409272d-1ff9-4e10-9fc9-ac0019c124fd")
    val YK5_NFC = Aaguid("a25342c0-3cdc-4414-8e46-f4807fca511c")
    val NOT_LISTED = Aaguid("00000000-0000-4000-8000-000000000001")

    private val V21 = listOf("FIDO_2_0", "FIDO_2_1", "U2F_V2")

    /** YubiKey Bio FIDO Edition 5.7.4, 0x1D aanwezig, alwaysUv standaard aan. */
    fun bioFido574(serial: Int = 31000001) = KeySpec(
        name = "Bio FIDO 5.7.4", aaguid = BIO_FIDO, firmware = Firmware(5, 7, 4), formFactor = KeyFormFactor.USB_C_BIO,
        serial = serial, versions = V21, bio = true, alwaysUv = true,
    )

    /** Bio met firmware 5.7.1: onder de Bio-grens 5.7.2 → STOP. */
    fun bio571() = bioFido574().copy(name = "Bio 5.7.1", firmware = Firmware(5, 7, 1))

    /** Bio met alwaysUv uit (attestation vóór de PIN, toggle). */
    fun bioAlwaysUvOff() = bioFido574().copy(name = "Bio alwaysUv uit", alwaysUv = false)

    /** Bio zonder 0x1D (onzekerheid 1). */
    fun bioNo1D() = bioFido574().copy(name = "Bio zonder 0x1D", maxPinReported = false)

    /** Bio MPE met PIV: maximaal 8 tekens, gemeld in 0x1D. */
    fun bioMpeMax8() = bioFido574().copy(name = "Bio MPE max 8", aaguid = BIO_MPE, maxPinActual = 8)

    /** Bio MPE met PIV zonder 0x1D: setPin(63) faalt met PIN_POLICY_VIOLATION. */
    fun bioMpeHidden() = bioMpeMax8().copy(name = "Bio MPE zonder 0x1D", maxPinReported = false)

    /** Bio FIDO die zich als FIDO voordoet maar stil max 8 heeft (proef met setPin). */
    fun bioFidoHiddenMax8() = bioNo1D().copy(name = "Bio FIDO stil max 8", maxPinActual = 8)

    /** YubiKey 5 NFC 5.4.2: geen FIDO 2.1-config. */
    fun yk5_542(serial: Int = 22000002) = KeySpec(
        name = "YK5 5.4.2", aaguid = YK5_NFC, firmware = Firmware(5, 4, 2), formFactor = KeyFormFactor.USB_A_KEYCHAIN,
        serial = serial, versions = listOf("FIDO_2_0", "FIDO_2_1_PRE", "U2F_V2"), bio = false, alwaysUv = null,
        setMinPinLengthOption = false, authnrCfg = false,
    )

    /** YubiKey 5 NFC 5.7.1, alwaysUv uit, U2F aanwezig. */
    fun yk5_57(serial: Int = 22000003) = KeySpec(
        name = "YK5 5.7.1", aaguid = YK5_NFC, firmware = Firmware(5, 7, 1), formFactor = KeyFormFactor.USB_A_KEYCHAIN,
        serial = serial, versions = V21, bio = false, alwaysUv = false,
    )

    fun yk5_569() = yk5_57().copy(name = "YK5 5.6.9", firmware = Firmware(5, 6, 9))

    fun yk5U2fStays() = yk5_57().copy(name = "YK5 houdt U2F", u2fStaysAfterAlwaysUv = true)

    val lookup = AaguidLookup { a ->
        when (a) {
            BIO_FIDO -> AaguidEntry(KeyClass.BIO, KeyVariant.FIDO, "YubiKey Bio Series - FIDO Edition")
            BIO_MPE -> AaguidEntry(KeyClass.BIO, KeyVariant.MPE, "YubiKey Bio Series - Multi-protocol Edition")
            YK5_NFC -> AaguidEntry(KeyClass.YUBIKEY5, KeyVariant.FIDO, "YubiKey 5 Series with NFC")
            else -> null
        }
    }

    val reportHasher = ReportSerialHasher(RawSerialKey(ByteArray(32) { (it * 7).toByte() }))

    fun inspector() = Inspector(lookup, nl.icthorse.horsesafe.yubikey.SerialHasher { s -> reportHasher.hash(s)!! })

    val CLOCK: () -> Instant = { Instant.parse("2026-10-12T10:00:00Z") }

    fun reports() = ReportFactory("0.3.0-Miller", CLOCK)
}

/**
 * Nagebootste AttestationVerifier: rpIdHash, packed + x5c, "keten" (leaf = [GENUINE_LEAF]), AAGUID in
 * authData, UP en (indien vereist) UV, ES256.
 */
object FakeAttestationJudge : AttestationJudge {
    val GENUINE_LEAF = "yubico-test-leaf".toByteArray()
    val FOREIGN_LEAF = "vreemde-ca-leaf".toByteArray()

    override fun judge(evidence: AttestationEvidence, expected: AttestExpectation): AttestOutcome {
        val ad = evidence.authData
        if (ad.size < 53) return AttestOutcome.Failed(Stop.ATTEST_FLAGS_INVALID)
        val rpHash = MessageDigest.getInstance("SHA-256").digest(expected.rpId.toByteArray())
        if (!ad.copyOfRange(0, 32).contentEquals(rpHash)) return AttestOutcome.Failed(Stop.ATTEST_RP_ID_HASH)
        if (evidence.fmt != "packed" || evidence.x5c.isEmpty()) return AttestOutcome.Failed(Stop.ATTEST_NOT_PACKED)
        if (!evidence.x5c[0].contentEquals(GENUINE_LEAF)) return AttestOutcome.Failed(Stop.ATTEST_CHAIN_INVALID)
        if (!ad.copyOfRange(37, 53).contentEquals(FakeYubiKey.uuidBytes(expected.aaguid))) return AttestOutcome.Failed(Stop.ATTEST_AAGUID_MISMATCH)
        val flags = ad[32].toInt()
        if (flags and 0x01 == 0 || (expected.requireUv && flags and 0x04 == 0) || flags and 0x40 == 0) return AttestOutcome.Failed(Stop.ATTEST_FLAGS_INVALID)
        if (evidence.alg != -7) return AttestOutcome.Failed(Stop.ATTEST_ALGORITHM)
        return AttestOutcome.Ok(ReportHashes.leafHash(evidence.x5c[0]))
    }
}
