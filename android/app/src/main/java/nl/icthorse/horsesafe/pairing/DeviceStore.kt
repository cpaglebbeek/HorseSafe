package nl.icthorse.horsesafe.pairing

import java.io.File
import java.io.IOException
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.keystore.KeySlot
import nl.icthorse.horsesafe.net.DeviceApi
import nl.icthorse.horsesafe.net.DeviceKey
import nl.icthorse.horsesafe.report.ReportSchemaException
import nl.icthorse.horsesafe.report.StrictJson

/** Lokale koppelstatus: `pending` tot de laptop bevestigt, daarna `active`. */
enum class LocalState { PENDING, ACTIVE }

/**
 * Wat de telefoon na het koppelen bewaart (§13.3 stap 2/5): device_id, de getoonde SAS (geen geheim), de
 * sleutels die de server meldt en `sk_c` ALLEEN gewikkeld met K_wrap (AES-256-GCM: [wrappedIv] + [wrappedCt]).
 * [slot] = de Keystore-sleutelset van deze koppeling (ontbreekt in oudere bestanden → A).
 */
class DeviceRecord(
    val deviceId: String,
    val state: LocalState,
    val sas: String,
    val label: String,
    val wrappedIv: ByteArray,
    val wrappedCt: ByteArray,
    val keys: List<DeviceKey>,
    val createdAt: Long,
    val slot: KeySlot = KeySlot.A,
) {
    fun with(state: LocalState = this.state, keys: List<DeviceKey> = this.keys) =
        DeviceRecord(deviceId, state, sas, label, wrappedIv, wrappedCt, keys, createdAt, slot)

    override fun toString(): String = "DeviceRecord(deviceId=$deviceId, state=$state, keys=${keys.size})"
}

/**
 * App-privéopslag van de koppeling: één JSON-bestand in `noBackupFilesDir/device/` (A-14: geen back-up,
 * geen device-transfer; allowBackup=false en de data-extraction-rules sluiten alles uit). Atomair schrijven
 * (tijdelijk bestand + rename). Een onleesbaar of afwijkend bestand telt als "geen koppeling".
 */
class DeviceStore(private val dir: File) {
    private val file get() = File(dir, FILE)

    @Synchronized
    fun load(): DeviceRecord? {
        val f = file
        if (!f.isFile || f.length() > MAX_BYTES) return null
        return try {
            fromJson(f.readText(Charsets.UTF_8))
        } catch (e: IOException) {
            null
        } catch (e: ReportSchemaException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    @Synchronized
    fun save(r: DeviceRecord) {
        if (!dir.isDirectory && !dir.mkdirs()) throw IOException("opslag niet beschikbaar")
        val tmp = File(dir, ".$FILE.tmp")
        tmp.writeText(toJson(r), Charsets.UTF_8)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw IOException("koppeling kon niet worden opgeslagen")
        }
    }

    /** Wist de koppeling (overschrijft eerst met nullen, dan verwijderen; best effort op flash). */
    @Synchronized
    fun wipe() {
        val f = file
        try {
            if (f.isFile) f.writeBytes(ByteArray(f.length().toInt().coerceAtMost(MAX_BYTES)))
        } catch (e: IOException) {
            // verwijderen volgt hieronder
        }
        f.delete()
        File(dir, ".$FILE.tmp").delete()
    }

    companion object {
        private const val FILE = "device.json"
        private const val MAX_BYTES = 16 * 1024

        internal fun toJson(r: DeviceRecord): String = StrictJson.write(
            linkedMapOf(
                "v" to 1,
                "device_id" to r.deviceId,
                "state" to r.state.name.lowercase(),
                "sas" to r.sas,
                "label" to r.label,
                "wrapped_iv" to B64u.encode(r.wrappedIv),
                "wrapped_ct" to B64u.encode(r.wrappedCt),
                "keys" to r.keys.map { linkedMapOf("key_id" to it.keyId, "vault_id" to it.vaultId, "label" to it.label) },
                "created_at" to r.createdAt,
                "slot" to r.slot.name.lowercase(),
            ),
        )

        internal fun fromJson(text: String): DeviceRecord {
            val o = StrictJson.parse(text) as? Map<*, *> ?: throw IllegalArgumentException("geen object")
            require(o["v"] == 1L) { "versie" }
            fun s(m: Map<*, *>, k: String) = m[k] as? String ?: throw IllegalArgumentException(k)
            val id = s(o, "device_id")
            require(DeviceApi.UUID.matches(id)) { "device_id" }
            val state = when (s(o, "state")) {
                "pending" -> LocalState.PENDING
                "active" -> LocalState.ACTIVE
                else -> throw IllegalArgumentException("state")
            }
            val keys = (o["keys"] as? List<*> ?: throw IllegalArgumentException("keys")).map {
                val m = it as? Map<*, *> ?: throw IllegalArgumentException("key")
                DeviceKey(s(m, "key_id"), s(m, "vault_id"), s(m, "label"))
            }
            return DeviceRecord(
                deviceId = id,
                state = state,
                sas = s(o, "sas"),
                label = s(o, "label"),
                wrappedIv = B64u.decode(s(o, "wrapped_iv"), 12),
                wrappedCt = B64u.decode(s(o, "wrapped_ct"), 48),
                keys = keys,
                createdAt = o["created_at"] as? Long ?: throw IllegalArgumentException("created_at"),
                slot = when (o["slot"]) {
                    null, "a" -> KeySlot.A
                    "b" -> KeySlot.B
                    else -> throw IllegalArgumentException("slot")
                },
            )
        }
    }
}
