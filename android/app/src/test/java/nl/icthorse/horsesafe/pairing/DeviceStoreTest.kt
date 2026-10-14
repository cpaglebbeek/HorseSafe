package nl.icthorse.horsesafe.pairing

import java.io.File
import java.nio.file.Files
import nl.icthorse.horsesafe.net.DeviceKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceStoreTest {
    private fun tmpDir(): File = Files.createTempDirectory("hs-device").toFile()

    private val rec = DeviceRecord(
        deviceId = "5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d",
        state = LocalState.PENDING,
        sas = "012345",
        label = "Galaxy – Fold",
        wrappedIv = ByteArray(12) { 7 },
        wrappedCt = ByteArray(48) { 9 },
        keys = listOf(DeviceKey("9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a", "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b", "Galaxy")),
        createdAt = 1_760_000_000L,
    )

    @Test fun opslaanLadenWissen() {
        val dir = tmpDir()
        try {
            val st = DeviceStore(dir)
            assertNull(st.load())
            st.save(rec)
            val back = st.load()!!
            assertEquals(rec.deviceId, back.deviceId)
            assertEquals(rec.state, back.state)
            assertEquals(rec.sas, back.sas)
            assertEquals(rec.label, back.label)
            assertArrayEquals(rec.wrappedIv, back.wrappedIv)
            assertArrayEquals(rec.wrappedCt, back.wrappedCt)
            assertEquals(rec.keys, back.keys)
            assertEquals(rec.createdAt, back.createdAt)
            st.wipe()
            assertNull(st.load())
            assertFalse(File(dir, "device.json").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun alleenGewikkeldeSleutelOpSchijf() {
        val json = DeviceStore.toJson(rec)
        assertTrue(json.contains("\"wrapped_ct\""))
        listOf("sk_c", "k_srv", "k_web", "\"s\"").forEach { assertFalse(json.contains(it)) }
    }

    @Test fun beschadigdBestandIsGeenKoppeling() {
        val dir = tmpDir()
        try {
            File(dir, "device.json").writeText("{\"v\":1}")
            assertNull(DeviceStore(dir).load())
            File(dir, "device.json").writeText(DeviceStore.toJson(rec).replace("\"pending\"", "\"weird\""))
            assertNull(DeviceStore(dir).load())
        } finally {
            dir.deleteRecursively()
        }
    }
}
