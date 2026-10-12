package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.Verdict

object ReportFixtures {
    val hasher = SerialHasher(RawSerialKey(ByteArray(32) { it.toByte() }))

    fun sample(
        createdAt: String = "2026-10-12T10:00:00Z",
        serial: Int? = 12345678,
        profile: Profile = Profile.BIO_MAIN,
    ) = Report(
        schemaVersion = 1,
        appVersion = "0.3.0-Miller",
        createdAt = createdAt,
        kind = ReportKind.SETUP,
        profile = profile,
        transport = "USB",
        aaguid = "90636e1f-ef82-43bf-bdcf-5255f139d12f",
        keyClass = "bio",
        variant = "fido",
        firmware = "5.7.4",
        firmwareSource = "MANAGEMENT",
        formFactor = "USB_C_BIO",
        serialHmac = hasher.hash(serial),
        versions = listOf("FIDO_2_0", "FIDO_2_1", "U2F_V2"),
        options = mapOf("clientPin" to true, "alwaysUv" to true, "bioEnroll" to true, "setMinPINLength" to true),
        rawPresent = mapOf("0x0C" to true, "0x0D" to true, "0x0E" to true, "0x1D" to true),
        minPinLength = 63,
        maxPinLength = 63,
        forcePinChange = false,
        pinRetries = 8,
        uvRetries = 3,
        residentCredentials = 0,
        fingerCount = 2,
        fingerNames = listOf("R-wijs", "L-wijs"),
        fingerTemplateHashes = listOf(ReportHashes.sha256Hex(byteArrayOf(1)), ReportHashes.sha256Hex(byteArrayOf(2))),
        attestationOk = true,
        attestationLeafSha256 = ReportHashes.sha256Hex(byteArrayOf(9, 9)),
        checks = listOf(
            CheckResult("fido_2_1", Verdict.GREEN, "FIDO 2.1 aanwezig."),
            CheckResult("firmware", Verdict.GREEN, "Firmware 5.7.4 — \"ok\" ✓"),
        ),
        stop = null,
        sealCode = null,
        paperLocationCode = "KLUIS-2",
        comparedWithPrevious = false,
        differences = emptyList(),
    )
}
