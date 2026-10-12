package nl.icthorse.horsesafe.yubikey.api

/**
 * F1 Herkennen (alleen lezen, elk profiel). Combineert [KeyLink.readManagement], [KeyLink.readRawInfo]
 * en een verse getInfo ([CtapPhase.freshInfo]) — elk in een eigen verbinding — tot [KeyFacts].
 * Klasse en variant komen uit de AAGUID-allowlist (assets/trust/aaguids.json, bytes door de app-laag
 * geïnjecteerd). Firmware bij voorkeur uit Management, anders 0x0E.
 */
interface InspectorOps {
    suspend fun inspect(link: KeyLink): KeyFacts
}
