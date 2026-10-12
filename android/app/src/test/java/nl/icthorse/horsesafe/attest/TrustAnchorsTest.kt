package nl.icthorse.horsesafe.attest

import nl.icthorse.horsesafe.attest.AttestTestData.allowlist
import nl.icthorse.horsesafe.attest.AttestTestData.backendData
import nl.icthorse.horsesafe.attest.AttestTestData.resource
import nl.icthorse.horsesafe.yubikey.api.Aaguid
import nl.icthorse.horsesafe.yubikey.api.KeyClass
import nl.icthorse.horsesafe.yubikey.api.KeyVariant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** [TrustRoots] en [AaguidAllowlist]: inlezen uit bytes, hashcontrole, fail-closed, MPE-herkenning. */
class TrustAnchorsTest {

    // ── TrustRoots ──

    @Test fun echteYubicoRootsZijnLeesbaar() {
        val bytes = backendData("yubico_fido_roots.pem").readBytes()
        val r = TrustRoots.fromPem(bytes, TrustRoots.sha256Hex(bytes))
        assertTrue(r.anchors.isNotEmpty())
        assertEquals(8, r.anchors.size + r.intermediates.size)
        assertTrue(r.anchors.all { TrustRoots.isSelfSigned(it.trustedCert) })
        assertTrue(r.intermediates.none { TrustRoots.isSelfSigned(it) })
    }

    @Test fun testRootsSplitsenInAnchorEnIntermediate() {
        val r = AttestTestData.testRoots
        assertEquals(1, r.anchors.size)
        assertEquals(1, r.intermediates.size)
        assertTrue(r.anchors[0].trustedCert.subjectX500Principal.name.contains("NIET VERTROUWEN"))
    }

    @Test fun afwijkendeHashVanRootsIsFout() {
        val bytes = resource("/attest/test_roots.pem")
        assertThrows(TrustRootsException::class.java) { TrustRoots.fromPem(bytes, "00".repeat(32)) }
    }

    @Test fun legeOfKapotteRootsZijnFout() {
        assertThrows(TrustRootsException::class.java) { TrustRoots.fromPem(ByteArray(0)) }
        assertThrows(TrustRootsException::class.java) { TrustRoots.fromPem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".toByteArray()) }
        assertTrue(TrustRoots.EMPTY.isEmpty)
    }

    @Test fun alleenIntermediateZonderRootIsFout() {
        // test_roots.pem = root + intermediate B; alleen het tweede certificaat overhouden.
        val text = resource("/attest/test_roots.pem").decodeToString()
        val second = text.substring(text.indexOf("-----BEGIN", 1))
        assertThrows(TrustRootsException::class.java) { TrustRoots.fromPem(second.toByteArray()) }
    }

    // ── AaguidAllowlist ──

    /** Alle Multi-protocol-AAGUID's uit MDS no. 290 (het plan noemt er vijf; de lijst bevat er negen). */
    private val mpe = setOf(
        "ba0a9266-40d8-4048-9786-d710b5474752",
        "9806a2c8-c0da-478e-b4ca-620005d34182",
        "dc5e949d-f939-43b3-9877-a85c7186b753",
        "34744913-4f57-4e6e-a527-e9ec3c4b94e6",
        "7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3",
        "90636e1f-ef82-43bf-bdcf-5255f139d12f",
        "6ec5cff2-a0f9-4169-945b-f33b563f7b99",
        "97e6a830-c952-4740-95fc-7c78dc97ce47",
        "58276709-bb4b-4bb3-baf1-60eea99282a7",
    ).map(::Aaguid).toSet()

    @Test fun echteLijstWordtGelezenMetHash() {
        val bytes = backendData("aaguids.json").readBytes()
        val l = AaguidAllowlist.fromJson(bytes, TrustRoots.sha256Hex(bytes).uppercase())
        assertEquals(TrustRoots.sha256Hex(bytes), l.sha256Hex)
        assertEquals(290L, l.mdsNo)
        assertTrue(l.size >= 50)
    }

    @Test fun mpeWordtHerkendAlsBioMpe() {
        assertEquals(mpe, allowlist.mpeAaguids())
        for (a in mpe) {
            val e = allowlist.lookup(a)!!
            assertEquals(KeyClass.BIO, e.keyClass) // server-json zegt "bio"
            assertEquals(KeyVariant.MPE, e.variant)
            assertEquals(AaguidAllowlist.APP_CLASS_BIO_MPE, allowlist.appClass(a))
        }
    }

    @Test fun bioFidoEnYk5ZijnGeenMpe() {
        val bio = Aaguid("9dd8d593-2213-438a-97f8-d6b813d51c27")
        assertEquals(KeyVariant.FIDO, allowlist.lookup(bio)!!.variant)
        assertEquals("bio", allowlist.appClass(bio))
        val yk5 = Aaguid("2fc0579f-8113-47ea-b116-bb5a8db9202a")
        assertEquals(KeyClass.YUBIKEY5, allowlist.lookup(yk5)!!.keyClass)
        assertEquals("yubikey5", allowlist.appClass(yk5))
        assertNull(allowlist.lookup(Aaguid("00112233-4455-6677-8899-aabbccddeeff")))
        assertNull(allowlist.appClass(Aaguid("00112233-4455-6677-8899-aabbccddeeff")))
    }

    private fun json(body: String) = """{"source":"t","aaguids":{$body}}""".toByteArray()

    @Test fun explicietVariantVeldEnHoofdletters() {
        val l = AaguidAllowlist.fromJson(
            json(
                """"AAAAAAAA-0000-0000-0000-000000000001":{"class":"bio","description":"x","variant":"mpe"},
                   "aaaaaaaa-0000-0000-0000-000000000002":{"class":"bio","description":"YubiKey Bio Multi-protocol Edition","variant":"fido"},
                   "aaaaaaaa-0000-0000-0000-000000000003":{"class":"bio","description":"YubiKey Bio"},
                   "aaaaaaaa-0000-0000-0000-000000000004":{"class":"security_key","description":"Security Key"}""",
            ),
        )
        assertEquals(KeyVariant.MPE, l.lookup(Aaguid("aaaaaaaa-0000-0000-0000-000000000001"))!!.variant)
        assertEquals(KeyVariant.MPE, l.lookup(Aaguid("aaaaaaaa-0000-0000-0000-000000000002"))!!.variant) // MPE wint
        assertEquals(KeyVariant.UNKNOWN, l.lookup(Aaguid("aaaaaaaa-0000-0000-0000-000000000003"))!!.variant)
        assertNull(l.lookup(Aaguid("aaaaaaaa-0000-0000-0000-000000000004"))) // onbekende klasse = niet toegestaan
        assertEquals(3, l.size)
    }

    @Test fun kapotteLijstIsFout() {
        assertThrows(AllowlistException::class.java) { AaguidAllowlist.fromJson("niet json".toByteArray()) }
        assertThrows(AllowlistException::class.java) { AaguidAllowlist.fromJson("""{"aaguids":[]}""".toByteArray()) }
        assertThrows(AllowlistException::class.java) { AaguidAllowlist.fromJson(json(""""geen-uuid":{"class":"bio"}""")) }
        assertThrows(AllowlistException::class.java) {
            AaguidAllowlist.fromJson(
                json(""""AAAAAAAA-0000-0000-0000-000000000001":{"class":"bio"},"aaaaaaaa-0000-0000-0000-000000000001":{"class":"bio"}"""),
            )
        }
        assertThrows(AllowlistException::class.java) { AaguidAllowlist.fromJson(byteArrayOf(0xff.toByte(), 0xfe.toByte())) }
    }

    @Test fun afwijkendeHashVanLijstIsFout() {
        val bytes = backendData("aaguids.json").readBytes()
        assertThrows(AllowlistException::class.java) { AaguidAllowlist.fromJson(bytes, "ab".repeat(32)) }
    }

    @Test fun legeLijstLaatNietsToe() {
        assertEquals(0, AaguidAllowlist.EMPTY.size)
        assertFalse(AaguidAllowlist.EMPTY.mpeAaguids().isNotEmpty())
    }
}
