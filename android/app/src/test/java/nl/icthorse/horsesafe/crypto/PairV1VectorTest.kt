package nl.icthorse.horsesafe.crypto

import nl.icthorse.horsesafe.pairing.PairingQr
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** pair_v1-vectoren (HARDWARE_KEYS §13.1): k_srv, k_web, QR, att_challenge, transcript, MAC's, SAS. */
class PairV1VectorTest {
    private val data = Vectors.load("pair_v1.json")
    private val vectors = Vectors.list(data, "vectors")

    private fun fields(v: Map<String, Any?>): PairV1.Fields {
        @Suppress("UNCHECKED_CAST")
        val f = v["fields"] as Map<String, String>
        return PairV1.Fields(f["pairing_id"]!!, f["pk_c"]!!, f["k_dev_pub"]!!, f["k_biosig_pub"]!!, f["label"]!!, f["model"]!!, f["app_version"]!!)
    }

    @Test fun formaat() {
        assertEquals("HorseSafe pair_v1 testvectors", data["format"])
        assertEquals(1L, data["version"])
        assertTrue(vectors.size >= 2)
    }

    @Test fun alleVectoren() {
        vectors.forEach { v ->
            val name = v["name"]
            val s = B64u.decode(v["s"] as String, 16)
            val kSrv = PairV1.kSrv(s)
            val kWeb = PairV1.kWeb(s)
            assertEquals("$name k_srv", v["k_srv"], B64u.encode(kSrv))
            assertEquals("$name k_web", v["k_web"], B64u.encode(kWeb))
            val f = fields(v)
            assertEquals("$name qr", v["qr"], PairingQr.PREFIX + f.pairingId + "." + B64u.encode(s))
            assertEquals("$name att_challenge", v["att_challenge_hex"], Vectors.hex(PairV1.attChallenge(f.pairingId, kSrv)))
            val t = PairV1.transcript(f)
            assertEquals("$name transcript", v["transcript_hex"], Vectors.hex(t))
            assertEquals("$name mac_srv", v["mac_srv"], B64u.encode(PairV1.mac(kSrv, t)))
            assertEquals("$name mac_web", v["mac_web"], B64u.encode(PairV1.mac(kWeb, t)))
            assertEquals("$name sas", v["sas"], PairV1.sas(t))
        }
    }

    /** De QR uit de vector gaat door de parser en levert hetzelfde id en geheim op. */
    @Test fun qrUitVectorParseert() {
        vectors.forEach { v ->
            val qr = PairingQr.parse(v["qr"] as String) ?: error("QR niet geparsed: ${v["name"]}")
            assertEquals(fields(v).pairingId, qr.pairingId)
            assertArrayEquals(B64u.decode(v["s"] as String), qr.secret)
            qr.wipe()
            assertTrue(qr.secret.all { it == 0.toByte() })
        }
    }

    @Test fun negatief() {
        Vectors.list(data, "negative").forEach { n ->
            val base = vectors.first { it["name"] == n["based_on"] }
            @Suppress("UNCHECKED_CAST")
            val change = n["change"] as Map<String, String>
            val f0 = fields(base)
            val f = f0.copy(label = change["label"] ?: f0.label)
            val s = B64u.decode(base["s"] as String)
            val t = PairV1.transcript(f)
            assertNotEquals(base["mac_srv"], B64u.encode(PairV1.mac(PairV1.kSrv(s), t)))
            assertNotEquals(base["mac_web"], B64u.encode(PairV1.mac(PairV1.kWeb(s), t)))
            assertNotEquals(base["sas"], PairV1.sas(t))
        }
    }

    /** Transcript-codering: velden in vaste volgorde, gescheiden door precies één 0x00, UTF-8, geen nultekens. */
    @Test fun transcriptCodering() {
        val f = PairV1.Fields("p", "a", "b", "c", "Ä é–", "m", "v")
        val t = PairV1.transcript(f)
        assertArrayEquals("HSv2 pair\u0000p\u0000a\u0000b\u0000c\u0000Ä é–\u0000m\u0000v".toByteArray(Charsets.UTF_8), t)
        assertEquals(7, t.count { it == 0.toByte() })
        assertThrows { PairV1.transcript(f.copy(label = "x\u0000y")) }
        assertThrows { PairV1.kSrv(ByteArray(15)) }
        assertThrows { PairV1.attChallenge("p", ByteArray(31)) }
    }

    @Test fun sasHeeftVoorloopnullen() {
        // Zoek een transcript waarvan de SAS met 0 begint en controleer de vorm.
        var i = 0
        while (true) {
            val sas = PairV1.sas("t$i".toByteArray())
            assertTrue(Regex("^[0-9]{6}$").matches(sas))
            if (sas.startsWith("0")) break
            i++
        }
    }

    private fun assertThrows(block: () -> Unit) {
        try {
            block()
        } catch (e: IllegalArgumentException) {
            return
        }
        throw AssertionError("verwacht IllegalArgumentException")
    }
}
