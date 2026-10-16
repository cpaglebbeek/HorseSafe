package nl.icthorse.horsesafe.net

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.URL
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import javax.net.ssl.HttpsURLConnection

/**
 * Eén HTTP-verzoek naar de device-API. [path] is relatief aan de basis-URL (begint met `/`).
 * [readTimeoutMs] = langere leestijd voor long-polling (`?wait=25`, §14.6); null = standaard.
 */
class HttpRequest(
    val method: String,
    val path: String,
    val body: ByteArray?,
    val headers: Map<String, String>,
    val readTimeoutMs: Int? = null,
)

/** Antwoord; [dateMillis] = de `Date`-header van de server (ms sinds 1970) of null (voor de klokwaarschuwing). */
class HttpResponse(val status: Int, val body: String, val dateMillis: Long? = null)

/** Abstractie zodat de API-laag in JVM-tests met een nep-transport draait (nooit productie). */
fun interface HttpTransport {
    @Throws(IOException::class)
    fun execute(req: HttpRequest): HttpResponse
}

/**
 * HTTPS via de platform-[HttpsURLConnection] (geen extra bibliotheek). De network-security-config laat alleen
 * icthorsecloud.nl toe en pint ISRG Root X1/X2; deze klasse controleert daarnaast zelf schema, host en poort,
 * volgt geen redirects, gebruikt geen cache en leest hooguit [MAX_BODY] bytes.
 */
class HttpsTransport(private val baseUrl: String) : HttpTransport {

    init {
        val u = URL(baseUrl)
        require(u.protocol == "https" && u.host == ALLOWED_HOST && (u.port == -1 || u.port == 443) && u.query == null && u.ref == null && u.userInfo == null) {
            "basis-URL niet toegestaan"
        }
    }

    override fun execute(req: HttpRequest): HttpResponse {
        require(req.path.startsWith("/") && !req.path.contains("..") && !req.path.contains("//")) { "ongeldig pad" }
        val url = URL(baseUrl + req.path)
        if (url.protocol != "https" || url.host != ALLOWED_HOST) throw IOException("host niet toegestaan")
        val c = url.openConnection() as HttpsURLConnection
        try {
            c.instanceFollowRedirects = false
            c.useCaches = false
            c.connectTimeout = CONNECT_TIMEOUT_MS
            c.readTimeout = (req.readTimeoutMs ?: READ_TIMEOUT_MS).coerceIn(READ_TIMEOUT_MS, MAX_READ_TIMEOUT_MS)
            c.requestMethod = req.method
            c.setRequestProperty("Accept", "application/json")
            req.headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
            val body = req.body
            if (body != null) {
                c.doOutput = true
                c.setRequestProperty("Content-Type", "application/json")
                c.setFixedLengthStreamingMode(body.size)
                c.outputStream.use { it.write(body) }
            }
            val status = c.responseCode
            val stream: InputStream? = if (status >= 400) c.errorStream else c.inputStream
            val text = stream?.use { decodeUtf8(readLimited(it)) } ?: ""
            return HttpResponse(status, text, c.date.takeIf { it > 0 })
        } finally {
            c.disconnect()
        }
    }

    private fun readLimited(input: InputStream): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            if (out.size() + n > MAX_BODY) throw IOException("antwoord te groot")
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    private fun decodeUtf8(b: ByteArray): String = try {
        Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(b)).toString()
    } catch (e: CharacterCodingException) {
        throw IOException("antwoord is geen UTF-8")
    }

    companion object {
        /** Gelijk aan de domain-config in res/xml/network_security_config.xml (bewaakt door een unit-test). */
        const val ALLOWED_HOST = "icthorsecloud.nl"
        const val MAX_BODY = 64 * 1024
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 20_000

        /** Bovengrens voor long-polling (wait=25 + marge). */
        private const val MAX_READ_TIMEOUT_MS = 45_000
    }
}
