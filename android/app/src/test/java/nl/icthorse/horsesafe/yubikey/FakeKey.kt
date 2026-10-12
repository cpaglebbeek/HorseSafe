package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.Transport as YkTransport
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.Cbor
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement
import nl.icthorse.horsesafe.pin.SecretBuffer

/**
 * CTAPHID-framing (FIDO U2F HID / CTAP 2.1 §11.2) bovenop een handler, zodat de ECHTE yubikit-code
 * (`FidoProtocol`, `Ctap2Session`, `ClientPin`, `Config`, ...) in de JVM-test meedraait.
 */
class FakeHidConnection(private val cbor: (ByteArray) -> ByteArray) : FidoConnection {
    private val outQueue = ArrayDeque<ByteArray>()
    private var reqCmd: Int = 0
    private var reqLen: Int = 0
    private var reqCid: Int = 0
    private var req = ByteArrayOutputStream()
    val commands = mutableListOf<Int>()

    override fun send(packet: ByteArray) {
        val bb = ByteBuffer.wrap(packet)
        val cid = bb.int
        val b = packet[4].toInt() and 0xFF
        if (b and 0x80 != 0) {
            reqCid = cid
            reqCmd = b
            reqLen = ((packet[5].toInt() and 0xFF) shl 8) or (packet[6].toInt() and 0xFF)
            req = ByteArrayOutputStream()
            req.write(packet, 7, minOf(57, reqLen))
        } else {
            req.write(packet, 5, minOf(59, reqLen - req.size()))
        }
        if (req.size() < reqLen) return
        if (reqCmd == 0x91) return // CTAPHID_CANCEL: geen antwoord
        val payload = req.toByteArray()
        commands += reqCmd
        val response = when (reqCmd) {
            0x86 -> payload.copyOf(8) + byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x02, 5, 7, 4, 0x05)
            0x90 -> cbor(payload)
            else -> byteArrayOf(0x01)
        }
        val cidOut = if (reqCmd == 0x86) reqCid else 0x01020304
        frame(cidOut, reqCmd, response)
    }

    private fun frame(cid: Int, cmd: Int, data: ByteArray) {
        var off = 0
        val first = ByteBuffer.allocate(64).putInt(cid).put(cmd.toByte()).putShort(data.size.toShort())
        val n0 = minOf(57, data.size)
        first.put(data, 0, n0)
        outQueue += first.array()
        off = n0
        var seq = 0
        while (off < data.size) {
            val p = ByteBuffer.allocate(64).putInt(cid).put(seq++.toByte())
            val n = minOf(59, data.size - off)
            p.put(data, off, n)
            outQueue += p.array()
            off += n
        }
    }

    override fun receive(packet: ByteArray) {
        val p = outQueue.removeFirstOrNull() ?: error("geen antwoord in de wachtrij")
        p.copyInto(packet)
    }

    override fun close() {}
}

/** Minimale ISO 7816-kant: SELECT FIDO → OK, NFCCTAP_MSG → [cbor]. Neemt elke APDU op. */
class FakeSmartCard(private val cbor: (ByteArray) -> ByteArray) : SmartCardConnection {
    val apdus = mutableListOf<ByteArray>()
    override fun sendAndReceive(apdu: ByteArray): ByteArray {
        apdus += apdu
        val ins = apdu[1].toInt() and 0xFF
        return when (ins) {
            0xA4 -> "U2F_V2".toByteArray() + byteArrayOf(0x90.toByte(), 0x00)
            0x10 -> {
                val lc = apdu[4].toInt() and 0xFF
                cbor(apdu.copyOfRange(5, 5 + lc)) + byteArrayOf(0x90.toByte(), 0x00)
            }
            else -> byteArrayOf(0x6D, 0x00)
        }
    }
    override fun getTransport(): YkTransport = YkTransport.NFC
    override fun isExtendedLengthApduSupported(): Boolean = false
    override fun getAtr(): ByteArray = ByteArray(0)
    override fun close() {}
}

/**
 * Spec-achtige nep-authenticator voor de CTAP-commando's die de adapters gebruiken. Neemt elk
 * verzoek op (gedecodeerd), zodat tests kunnen nagaan WAT er naar de sleutel ging.
 */
class FakeAuthenticator {
    val options = linkedMapOf<String, Any>(
        "rk" to true, "up" to true, "plat" to false, "clientPin" to false,
        "credMgmt" to true, "authnrCfg" to true, "setMinPINLength" to true,
        "pinUvAuthToken" to true, "alwaysUv" to false, "makeCredUvNotRqd" to true,
    )
    var versions = listOf("U2F_V2", "FIDO_2_0", "FIDO_2_1")
    var aaguid: ByteArray = ByteArray(16) { (0x10 + it).toByte() }
    var protocols = listOf(2, 1)
    var minPinLength = 4
    var extraInfo = mutableMapOf<Int, Any>()
    var pinRetries = 8
    var uvRetries = 3
    var pinTokenError: Int? = null
    val pinToken: ByteArray = ByteArray(32) { (0x40 + it).toByte() }
    var correctPin: CharArray? = null

    /** Alle verzoeken: (ctap-commando, gedecodeerde map). */
    val requests = mutableListOf<Pair<Int, Map<*, *>>>()

    private val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
    private var shared: ByteArray? = null
    val v2 = PinUvAuthProtocolV2()

    fun clientPinRequests(): List<Map<*, *>> = requests.filter { it.first == 0x06 }.map { it.second }
    fun subcommands(): List<Int> = clientPinRequests().map { it[2] as Int }

    fun handle(data: ByteArray): ByteArray {
        val cmd = data[0].toInt() and 0xFF
        val req: Map<*, *> = if (data.size > 1) Cbor.decode(data, 1, data.size - 1) as Map<*, *> else emptyMap<Any, Any>()
        requests += cmd to req
        return when (cmd) {
            0x04 -> ok(info())
            0x06 -> clientPin(req)
            0x0D -> config(req)
            0x01 -> ok(
                mapOf(
                    1 to "packed",
                    2 to ByteArray(37 + 16) { 7 },
                    3 to mapOf("alg" to -7, "sig" to byteArrayOf(1, 2, 3), "x5c" to listOf(byteArrayOf(0x30, 0x01))),
                ),
            )
            0x0A -> ok(mapOf(1 to 0, 2 to 25))
            else -> byteArrayOf(0x01)
        }
    }

    fun info(): Map<Int, Any> = buildMap {
        put(0x01, versions)
        put(0x03, aaguid)
        put(0x04, options)
        put(0x06, protocols)
        put(0x0D, minPinLength)
        put(0x10, 1)
        putAll(extraInfo)
    }

    private fun clientPin(req: Map<*, *>): ByteArray = when (req[2] as Int) {
        0x01 -> ok(mapOf(3 to pinRetries))
        0x07 -> ok(mapOf(5 to uvRetries))
        0x02 -> {
            val pub = keyPair.public as ECPublicKey
            ok(mapOf(1 to mapOf(1 to 2, 3 to -25, -1 to 1, -2 to coord(pub.w.affineX), -3 to coord(pub.w.affineY))))
        }
        0x09, 0x05 -> {
            agree(req[3] as Map<*, *>)
            val err = pinTokenError
            if (err != null) {
                byteArrayOf(err.toByte())
            } else {
                ok(mapOf(2 to v2.encrypt(shared!!, pinToken)))
            }
        }
        0x03 -> {
            agree(req[3] as Map<*, *>)
            options["clientPin"] = true
            byteArrayOf(0x00)
        }
        else -> byteArrayOf(0x02)
    }

    private fun config(req: Map<*, *>): ByteArray {
        when (req[1] as Int) {
            0x02 -> options["alwaysUv"] = !(options["alwaysUv"] as Boolean)
            0x03 -> minPinLength = ((req[2] as Map<*, *>)[1] as Int)
        }
        return byteArrayOf(0x00)
    }

    /** Decodeert pinHashEnc van het laatste getPinToken-verzoek (voor de test). */
    fun lastPinHash(): ByteArray {
        val r = clientPinRequests().last { (it[2] as Int) == 0x09 || (it[2] as Int) == 0x05 }
        return v2.decrypt(shared!!, r[6] as ByteArray)
    }

    private fun agree(platformKey: Map<*, *>) {
        val x = BigInteger(1, platformKey[-2] as ByteArray)
        val y = BigInteger(1, platformKey[-3] as ByteArray)
        val params = (keyPair.public as ECPublicKey).params
        val other = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(keyPair.private)
        ka.doPhase(other, true)
        shared = v2.kdf(ka.generateSecret())
    }

    private fun coord(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == 32 -> b
            b.size > 32 -> b.copyOfRange(b.size - 32, b.size)
            else -> ByteArray(32 - b.size) + b
        }
    }

    companion object {
        fun ok(map: Map<*, *>): ByteArray = byteArrayOf(0x00) + Cbor.encode(map)
        fun pinHashOf(pin: CharArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(String(pin).toByteArray()).copyOf(16)
    }
}

/** Eenvoudige [SecretBuffer] voor tests (de echte zit in pin/). */
class TestSecret(text: String) : SecretBuffer {
    private val chars = text.toCharArray()
    private var wiped = false
    override val capacity: Int = chars.size
    override val length: Int get() = if (wiped) 0 else chars.size
    override val isWiped: Boolean get() = wiped
    override fun append(c: Char) = throw UnsupportedOperationException()
    override fun removeLast() = throw UnsupportedOperationException()
    override fun get(index: Int): Char = chars[index]
    override fun <T> useChars(block: (CharArray) -> T): T = block(chars)
    override fun wipe() { chars.fill('\u0000'); wiped = true }
    override fun toString(): String = SecretBuffer.HIDDEN
}
