package nl.icthorse.horsesafe.report

/**
 * Whitelist voor [Report]. Serialisatie en import gaan uitsluitend hierdoorheen.
 * - [allowedFields] = precies de property-namen van [Report] (een test bewaakt de gelijkheid);
 * - [toJson] faalt met [ReportSchemaException] als het rapport een veld buiten de whitelist zou opleveren;
 * - [fromJson] (import via SAF) weigert elk onbekend of ontbrekend veld en een andere [version].
 * Geen bestand- of netwerkcode hier: lezen/schrijven doet `ReportStore` met de opslagkiezer.
 */
interface ReportSchema {
    val version: Int
    val allowedFields: Set<String>

    fun toJson(report: Report): String

    fun fromJson(json: String): Report
}
