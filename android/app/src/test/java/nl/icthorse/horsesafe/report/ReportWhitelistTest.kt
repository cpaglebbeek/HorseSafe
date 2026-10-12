package nl.icthorse.horsesafe.report

import nl.icthorse.horsesafe.flow.CheckResult
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.flow.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.lang.reflect.Modifier

class ReportWhitelistTest {
    private val schema: ReportSchema = ReportJsonSchema
    private val r = ReportFixtures.sample()

    private fun rejects(json: String, why: String) {
        try {
            schema.fromJson(json)
            fail("verwacht ReportSchemaException: $why")
        } catch (e: ReportSchemaException) {
            // ok
        }
    }

    @Test fun whitelistIsPreciesDeReportVelden() {
        val props = Report::class.java.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }.map { it.name }.toSet()
        assertEquals(props, schema.allowedFields)
        assertEquals(ReportJsonSchema.FIELDS.size, ReportJsonSchema.FIELDS.toSet().size)
        assertEquals(1, schema.version)
    }

    @Test fun rondreis() {
        val json = schema.toJson(r)
        assertTrue(json.all { it.code in 0x20..0x7e })
        assertEquals(r, schema.fromJson(json))
        assertEquals(json, schema.toJson(schema.fromJson(json)))
        // Met stop en nulls.
        val s = r.copy(stop = Stop.KEY_REMOVED.name, firmware = null, serialHmac = null, fingerNames = null, checks = emptyList())
        assertEquals(s, schema.fromJson(schema.toJson(s)))
    }

    @Test fun onbekendVeldWordtGeweigerd() {
        val json = schema.toJson(r)
        rejects(json.dropLast(1) + ",\"pin\":\"x\"}", "extra veld pin")
        rejects(json.dropLast(1) + ",\"serial\":12345678}", "extra veld serial")
        rejects(json.dropLast(1) + ",\"extra\":null}", "extra veld met null")
        rejects(json.replace("\"detail\":\"FIDO 2.1 aanwezig.\"", "\"detail\":\"FIDO 2.1 aanwezig.\",\"token\":\"x\""), "extra veld in check")
        rejects(json.replace("\"0x1D\":true", "\"0x1D\":true,\"0x10\":true"), "extra rawPresent-sleutel")
    }

    @Test fun ontbrekendDubbelOfFoutTypeWordtGeweigerd() {
        val json = schema.toJson(r)
        rejects(json.replace(",\"stop\":null", ""), "ontbrekend veld")
        rejects(json.replace("\"stop\":null", "\"stop\":null,\"stop\":null"), "dubbel veld")
        rejects(json.replace("\"schemaVersion\":1", "\"schemaVersion\":2"), "andere schemaversie")
        rejects(json.replace("\"pinRetries\":8", "\"pinRetries\":8.0"), "breuk")
        rejects(json.replace("\"pinRetries\":8", "\"pinRetries\":\"8\""), "string i.p.v. getal")
        rejects(json.replace("\"stop\":null", "\"stop\":\"BESTAAT_NIET\""), "onbekende stop")
        rejects(json.replace("\"kind\":\"SETUP\"", "\"kind\":\"setup\""), "onbekende kind")
        rejects(json.replace("\"createdAt\":\"2026-10-12T10:00:00Z\"", "\"createdAt\":\"2026-13-12T10:00:00Z\""), "ongeldige datum")
        rejects(json.replace("\"aaguid\":\"90636e1f", "\"aaguid\":\"90636E1F"), "AAGUID niet canoniek")
        rejects(json + " x", "tekst na einde")
        rejects("[]", "geen object")
        rejects("", "leeg")
        rejects("{\"a\":", "afgekapt")
        rejects(json.replace("\"variant\":\"fido\"", "\"variant\":\"FIDO\""), "variant hoofdletters")
    }

    @Test fun toJsonWeigertOngeldigeWaarden() {
        listOf(
            r.copy(schemaVersion = 2),
            r.copy(stop = "GEEN_STOP"),
            r.copy(serialHmac = "12345678"),
            r.copy(transport = "BLE"),
            r.copy(sealCode = "met spatie"),
            r.copy(rawPresent = r.rawPresent - "0x1D"),
            r.copy(checks = listOf(CheckResult("Hoofdletter", Verdict.GREEN, "x"))),
        ).forEach {
            try { schema.toJson(it); fail("verwacht ReportSchemaException") } catch (e: ReportSchemaException) { }
        }
    }

    @Test fun geenSerienummerOfGeheimeVeldnamen() {
        val json = schema.toJson(r).lowercase()
        assertFalse(json.contains("12345678"))
        listOf("\"pin\"", "token", "pinuvauthparam", "sharedsecret", "credentialid", "publickey", "\"serial\"").forEach {
            assertFalse(it, json.contains(it))
        }
        assertTrue(SerialHasher.FORMAT.matches(r.serialHmac!!))
    }

    @Test fun strikteJson() {
        rejects(schema.toJson(r).replace("R-wijs", "R-\\x"), "ongeldige escape")
        rejects(schema.toJson(r).replace("R-wijs", "R-\\ud800"), "ongepaard surrogaat")
        rejects(schema.toJson(r).replace("R-wijs", "R-\u0001"), "stuurteken")
        var deep = "1"
        repeat(20) { deep = "[$deep]" }
        rejects("{\"a\":$deep}", "te diep")
        rejects("{\"schemaVersion\":1" + " ".repeat(ReportJsonSchema.MAX_CHARS) + "}", "te groot")
    }
}
