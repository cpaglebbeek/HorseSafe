package nl.icthorse.horsesafe.net

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** DeviceApi tegen een nep-transport (nooit de echte server): paden, headers, strikte antwoorden. */
class DeviceApiTest {
    private val dev = "5b1e2c3d-4f50-4a6b-8c7d-9e0f1a2b3c4d"
    private val kid = "9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a"
    private val vid = "3f2a1b4c-5d6e-4f70-8a9b-0c1d2e3f4a5b"
    private val signer = DevKeySigner { ByteArray(8) { 1 } }

    private class Fake(val reply: (HttpRequest) -> HttpResponse) : HttpTransport {
        val seen = mutableListOf<HttpRequest>()
        override fun execute(req: HttpRequest): HttpResponse {
            seen += req
            return reply(req)
        }
    }

    private fun claimReq() = ClaimRequest("pk", "dev", "bio", listOf("a", "b"), listOf("c", "d"), "Label – é", "M", "0.3.4-Miller", "ms", "mw", "sig")

    @Test fun claimPadEnBody() {
        val t = Fake { HttpResponse(201, "{\"device_id\":\"$dev\",\"sas\":\"012345\"}") }
        val r = DeviceApi(t).claim(kid, claimReq())
        assertEquals(ClaimResponse(dev, "012345"), r)
        val req = t.seen.single()
        assertEquals("POST", req.method)
        assertEquals("/devices/pairings/$kid/claim", req.path)
        assertTrue("claim is publiek: geen device-headers", req.headers.isEmpty())
        val body = String(req.body!!, Charsets.UTF_8)
        assertEquals(
            "{\"pk_c\":\"pk\",\"k_dev_pub\":\"dev\",\"k_biosig_pub\":\"bio\",\"k_dev_chain\":[\"a\",\"b\"],\"k_biosig_chain\":[\"c\",\"d\"]," +
                "\"label\":\"Label \\u2013 \\u00e9\",\"model\":\"M\",\"app_version\":\"0.3.4-Miller\",\"mac_srv\":\"ms\",\"mac_web\":\"mw\",\"sig_biosig\":\"sig\"}",
            body,
        )
    }

    @Test fun statusIsGetekendMetApiPad() {
        val t = Fake { HttpResponse(200, "{\"device_id\":\"$dev\",\"state\":\"active\",\"keys\":[{\"key_id\":\"$kid\",\"vault_id\":\"$vid\",\"label\":\"Galaxy\"}]}") }
        val s = DeviceApi(t, clockSeconds = { 1000L }).status(dev, signer)
        assertEquals(DeviceState.ACTIVE, s.state)
        assertEquals(listOf(DeviceKey(kid, vid, "Galaxy")), s.keys)
        val req = t.seen.single()
        assertEquals("/device/v1/status", req.path)
        assertEquals(null, req.body)
        assertEquals(dev, req.headers["X-HS-Device"])
        assertEquals("1000", req.headers["X-HS-Ts"])
        assertEquals(4, req.headers.size)
    }

    @Test fun dateHeaderVanFoutantwoordGaatMee() {
        val t = Fake { HttpResponse(401, "{\"detail\":{\"error\":\"device_auth_failed\"}}", 1_800_000_000_000L) }
        try {
            DeviceApi(t).status(dev, signer)
            fail()
        } catch (e: ApiException) {
            assertEquals(401, e.status)
            assertEquals("device_auth_failed", e.code)
            assertEquals(1_800_000_000_000L, e.serverDateMillis)
        }
        try {
            DeviceApi({ throw IOException("weg") }).status(dev, signer)
            fail()
        } catch (e: ApiException) {
            assertEquals(null, e.serverDateMillis)
        }
    }

    @Test fun foutcodeUitDetail() {
        val t = Fake { HttpResponse(400, "{\"detail\":{\"error\":\"attestation_invalid\",\"reason\":\"boot_state\"}}") }
        try {
            DeviceApi(t).claim(kid, claimReq())
            fail()
        } catch (e: ApiException) {
            assertEquals(400, e.status)
            assertEquals("attestation_invalid", e.code)
            assertEquals("boot_state", e.reason)
        }
    }

    @Test fun onverwachteAntwoordenGeweigerd() {
        listOf(
            HttpResponse(201, "{\"device_id\":\"$dev\",\"sas\":\"12345\"}"),
            HttpResponse(201, "{\"device_id\":\"x\",\"sas\":\"123456\"}"),
            HttpResponse(201, "<html>"),
            HttpResponse(200, "{\"device_id\":\"$dev\",\"sas\":\"123456\"}"),
        ).forEach { resp ->
            try {
                DeviceApi(Fake { resp }).claim(kid, claimReq())
                fail("geaccepteerd: ${resp.body}")
            } catch (e: ApiException) {
                // goed
            }
        }
        // status van een ander toestel of onbekende state
        listOf(
            "{\"device_id\":\"$kid\",\"state\":\"active\",\"keys\":[]}",
            "{\"device_id\":\"$dev\",\"state\":\"weird\",\"keys\":[]}",
            "{\"device_id\":\"$dev\",\"state\":\"active\"}",
        ).forEach { body ->
            try {
                DeviceApi(Fake { HttpResponse(200, body) }).status(dev, signer)
                fail("geaccepteerd: $body")
            } catch (e: ApiException) {
                // goed
            }
        }
    }

    @Test fun netwerkfoutWordtStatus0() {
        try {
            DeviceApi({ throw IOException("weg") }).status(dev, signer)
            fail()
        } catch (e: ApiException) {
            assertEquals(0, e.status)
            assertEquals("network", e.code)
        }
    }

    @Test fun padInjectieGeweigerd() {
        try {
            DeviceApi(Fake { HttpResponse(200, "{}") }).sealed(dev, "../x", signer)
            fail()
        } catch (e: IllegalArgumentException) {
            // goed
        }
    }

    @Test fun transportAlleenNaarEigenHost() {
        listOf("http://icthorsecloud.nl/HorseSafe/api", "https://example.org/api", "https://icthorsecloud.nl:8443/api", "https://icthorsecloud.nl.evil.nl/api")
            .forEach { url ->
                try {
                    HttpsTransport(url)
                    fail("toegestaan: $url")
                } catch (e: IllegalArgumentException) {
                    // goed
                }
            }
        HttpsTransport("https://icthorsecloud.nl/HorseSafe/api") // geen verbinding: alleen de constructor
    }
}
