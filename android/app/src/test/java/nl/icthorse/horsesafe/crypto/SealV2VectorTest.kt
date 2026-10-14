package nl.icthorse.horsesafe.crypto

import nl.icthorse.horsesafe.report.StrictJson
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * Seal_v2-vectoren (HARDWARE_KEYS §12.5) met de platform-XDH van de JVM: PRF → sleutelpaar, verzegelen
 * byte voor byte (AAD, pt, k, sealed), openen, en de negatieve gevallen (`unseal_failed`).
 */
class SealV2VectorTest {
    private val data = Vectors.load("seal_v2.json")
    private val seals = Vectors.list(data, "seal_vectors")

    private fun b(s: Any?): ByteArray = B64u.decode(s as String)
    private fun bOrNull(s: Any?): ByteArray? = (s as String?)?.let { B64u.decode(it) }

    @Test fun formaat() {
        assertEquals("HorseSafe Seal_v2 testvectors", data["format"])
        assertEquals(setOf("ph+kh", "alleen ph", "alleen kh"), seals.map { it["name"] }.toSet())
    }

    @Test fun prfNaarSleutelpaar() {
        Vectors.list(data, "prf_vectors").forEach { v ->
            val seed = Hkdf.sha256(b(v["prf"]), ByteArray(32), "HorseSafe v2 X25519")
            assertEquals("sk", v["sk"], B64u.encode(seed))
            assertEquals("pk", v["pk"], B64u.encode(X25519.publicKey(seed)))
        }
    }

    @Test fun verzegelenByteVoorByte() {
        seals.forEach { v ->
            val name = v["name"]
            assertEquals("$name recipient_pk", v["recipient_pk"], B64u.encode(X25519.publicKey(b(v["recipient_sk"]))))
            assertEquals("$name ephemeral_pk", v["ephemeral_pk"], B64u.encode(X25519.publicKey(b(v["ephemeral_sk"]))))
            val aad = SealV2.aad(v["purpose"] as String, v["vault_id"] as String, v["bind"] as String)
            assertEquals("$name aad", v["aad_hex"], Vectors.hex(aad))
            val pt = SealV2.plaintext(bOrNull(v["ph"]), bOrNull(v["kh"]))
            assertEquals("$name pt", v["pt_utf8"], String(pt, Charsets.UTF_8))
            val ss = X25519.sharedSecret(b(v["ephemeral_sk"]), b(v["recipient_pk"]))
            val k = SealV2.sealKey(ss, b(v["ephemeral_pk"]), b(v["recipient_pk"]))
            assertEquals("$name k", v["k_hex"], Vectors.hex(k))
            val sealed = SealV2.sealWith(
                b(v["recipient_pk"]), bOrNull(v["ph"]), bOrNull(v["kh"]),
                v["purpose"] as String, v["vault_id"] as String, v["bind"] as String, v["kid"] as String,
                b(v["ephemeral_sk"]), b(v["iv"]),
            )
            assertEquals("$name sealed", v["sealed"], sealed)
        }
    }

    @Test fun openen() {
        seals.forEach { v ->
            val secret = SealV2.open(v["sealed"] as String, b(v["recipient_sk"]), "store", v["vault_id"] as String, v["kid"] as String)
            val ph = bOrNull(v["ph"])
            val kh = bOrNull(v["kh"])
            if (ph == null) assertNull(secret.ph) else assertArrayEquals(ph, secret.ph)
            if (kh == null) assertNull(secret.kh) else assertArrayEquals(kh, secret.kh)
            secret.wipe()
            assertTrue(secret.ph?.all { it == 0.toByte() } ?: true)
            assertEquals("SealedSecret([verborgen])", secret.toString())
        }
    }

    @Test fun negatieveVectoren() {
        Vectors.list(data, "negative").forEach { n ->
            val base = seals.first { it["name"] == n["based_on"] }
            @Suppress("UNCHECKED_CAST")
            val w = n["open_with"] as Map<String, String>
            expectFail(n["expect"] as String, n["name"] as String) {
                SealV2.open(
                    w["sealed"] ?: base["sealed"] as String,
                    b(base["recipient_sk"]),
                    w["purpose"] ?: "store",
                    w["vault_id"] ?: base["vault_id"] as String,
                    w["key_id"] ?: base["kid"] as String,
                )
            }
        }
    }

    @Test fun extraNegatieveGevallen() {
        val v = seals.first()
        val sealed = v["sealed"] as String
        val sk = b(v["recipient_sk"])
        val vid = v["vault_id"] as String
        val kid = v["kid"] as String
        val obj = StrictJson.parse(sealed) as Map<*, *>
        fun mutate(change: (LinkedHashMap<String, Any?>) -> Unit): String {
            val m = LinkedHashMap<String, Any?>()
            obj.forEach { (k, x) -> m[k as String] = x }
            change(m)
            return StrictJson.write(m)
        }
        // verkeerde ontvanger
        expectFail("unseal_failed", "andere sk") { SealV2.open(sealed, b(seals[1]["recipient_sk"]), "store", vid, kid) }
        // vorm
        expectFail("invalid_sealed", "v=1") { SealV2.open(mutate { it["v"] = 1 }, sk, "store", vid, kid) }
        expectFail("invalid_sealed", "extra sleutel") { SealV2.open(mutate { it["x"] = "y" }, sk, "store", vid, kid) }
        expectFail("invalid_sealed", "ontbrekende ct") { SealV2.open(mutate { it.remove("ct") }, sk, "store", vid, kid) }
        expectFail("invalid_sealed", "iv te kort") { SealV2.open(mutate { it["iv"] = "AAAA" }, sk, "store", vid, kid) }
        expectFail("invalid_sealed", "epk met =") { SealV2.open(mutate { it["epk"] = (it["epk"] as String).dropLast(1) + "=" }, sk, "store", vid, kid) }
        expectFail("invalid_sealed", "geen JSON") { SealV2.open("{", sk, "store", vid, kid) }
        expectFail("invalid_sealed", "te lang") { SealV2.open(" ".repeat(1025), sk, "store", vid, kid) }
        // kid in sealed past niet bij de verwachte key_id (AAD wordt toch uit key_id gebouwd)
        expectFail("unseal_failed", "andere kid") { SealV2.open(mutate { it["kid"] = "11111111-1111-4111-8111-111111111111" }, sk, "store", vid, kid) }
        // lage-orde-punt als epk: gedeeld geheim nul → weigeren
        expectFail("unseal_failed", "epk nul") { SealV2.open(mutate { it["epk"] = B64u.encode(ByteArray(32)) }, sk, "store", vid, kid) }
    }

    @Test fun plaintextVorm() {
        val a = ByteArray(32) { 1 }
        val ok = SealV2.parsePlaintext(SealV2.plaintext(a, null))
        assertArrayEquals(a, ok.ph)
        assertNull(ok.kh)
        listOf(
            "{\"ph\":null,\"kh\":null}",
            "{\"kh\":null,\"ph\":null}",
            "{\"ph\": null,\"kh\":null}",
            "{\"ph\":\"" + "A".repeat(42) + "\",\"kh\":null}",
            "{\"ph\":\"" + "A".repeat(42) + "B\",\"kh\":null}", // niet-canoniek (laatste bits niet 0)
            "{\"ph\":\"" + B64u.encode(a) + "\",\"kh\":null} ",
            "{\"ph\":\"" + B64u.encode(a) + "\",\"kh\":null,\"x\":1}",
        ).forEach { bad ->
            try {
                SealV2.parsePlaintext(bad.toByteArray())
                fail("geaccepteerd: $bad")
            } catch (e: SealException) {
                assertEquals("unseal_failed", e.code)
            }
        }
        try {
            SealV2.plaintext(null, null)
            fail("leeg ck geaccepteerd")
        } catch (e: IllegalArgumentException) {
            // goed
        }
    }

    /** Willekeurig verzegelen + openen (zelfde route als de web-client). */
    @Test fun rondgang() {
        val sk = X25519.newPrivate()
        val pk = X25519.publicKey(sk)
        val ph = ByteArray(32) { it.toByte() }
        val sealed = SealV2.seal(pk, ph, null, "store", "v", "k", "k")
        val s = SealV2.open(sealed, sk, "store", "v", "k")
        assertArrayEquals(ph, s.ph)
        assertTrue(sealed.length <= 1024)
    }

    private fun expectFail(code: String, name: String, block: () -> Unit) {
        try {
            block()
            fail("$name: geen fout")
        } catch (e: SealException) {
            assertEquals(name, code, e.code)
        }
    }
}
