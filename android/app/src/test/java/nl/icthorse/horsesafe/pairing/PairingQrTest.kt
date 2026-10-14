package nl.icthorse.horsesafe.pairing

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/** QR-parsing `hs1p:<pairing_id>.<b64u(s)>` (HARDWARE_KEYS §13.1): strikt, geen geheim in toString. */
class PairingQrTest {
    private val id = "5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d"
    private val s = "J5TKFXDAKqzRTv2u1PIbgg"

    @Test fun geldig() {
        val q = PairingQr.parse("hs1p:$id.$s")
        assertNotNull(q)
        assertEquals(id, q!!.pairingId)
        assertEquals(16, q.secret.size)
        assertFalse(q.toString().contains(s))
    }

    @Test fun ongeldig() {
        listOf(
            "",
            "hs1p:",
            "HS1P:$id.$s",
            "hs1p:$id",
            "hs1p:$id.",
            "hs1p:.$s",
            " hs1p:$id.$s",
            "hs1p:$id.$s ",
            "hs1p:$id.$s\n",
            "hs1p:$id.$s.x",
            "hs1p:${id.uppercase()}.$s",
            "hs1p:5b1e2c3d4f504a6b8c7d9e0f1a2b3c4d.$s",
            "hs1p:$id.${s}A",
            "hs1p:$id.${s.dropLast(1)}",
            "hs1p:$id.${s.dropLast(1)}h", // niet-canoniek (laatste bits niet 0)
            "hs1p:$id.J5TKFXDAKqzRTv2u1PIbgg==",
            "hs1p:$id.J5TKFXDAKqzRTv2u1PI+gg",
            "https://icthorsecloud.nl/HorseSafe/",
            "hs1p:$id.$s" + "x".repeat(80),
        ).forEach { assertNull("geaccepteerd: '$it'", PairingQr.parse(it)) }
    }
}
