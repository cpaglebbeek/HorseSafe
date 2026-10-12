package nl.icthorse.horsesafe.attest

import java.io.File
import nl.icthorse.horsesafe.report.StrictJson
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.AttestationEvidence
import nl.icthorse.horsesafe.yubikey.api.KeyClass

/** Laadt de synthetische vectoren (eigen test-CA, geen Yubico) en de echte vertrouwensbestanden. */
internal object AttestTestData {
    fun resource(path: String): ByteArray =
        requireNotNull(AttestTestData::class.java.getResourceAsStream(path)) { "resource ontbreekt: $path" }.use { it.readBytes() }

    /** `backend/data/<name>` vanaf de werkmap van Gradle (android/app) of android/. */
    fun backendData(name: String): File =
        listOf("../../backend/data/$name", "../backend/data/$name", "backend/data/$name")
            .map(::File).first { it.isFile }

    val testRoots: TrustRoots by lazy { TrustRoots.fromPem(resource("/attest/test_roots.pem")) }
    val foreignRoots: TrustRoots by lazy { TrustRoots.fromPem(resource("/attest/foreign_root.pem")) }
    val allowlist: AaguidAllowlist by lazy { AaguidAllowlist.fromJson(backendData("aaguids.json").readBytes()) }

    class Vector(
        val id: String,
        val evidence: AttestationEvidence,
        val expectedAaguid: Aaguid,
        val expectedClass: KeyClass,
        val expect: String,
        val reason: String?,
    )

    val vectors: List<Vector> by lazy {
        val doc = StrictJson.parse(resource("/attest/vectors.json").decodeToString()) as Map<*, *>
        (doc["vectors"] as List<*>).map { raw ->
            val v = raw as Map<*, *>
            Vector(
                id = v["id"] as String,
                evidence = AttestationEvidence(
                    fmt = v["fmt"] as String,
                    authData = hex(v["authData"] as String),
                    alg = (v["alg"] as Long?)?.toInt(),
                    sig = hex(v["sig"] as String),
                    x5c = (v["x5c"] as List<*>).map { hex(it as String) },
                    clientDataHash = hex(v["clientDataHash"] as String),
                    rpId = v["rpId"] as String,
                    withToken = v["withToken"] as Boolean,
                ),
                expectedAaguid = Aaguid(v["expectedAaguid"] as String),
                expectedClass = KeyClass.valueOf(v["expectedClass"] as String),
                expect = v["expect"] as String,
                reason = v["reason"] as String?,
            )
        }
    }

    fun vector(id: String): Vector = vectors.first { it.id == id }

    fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}
