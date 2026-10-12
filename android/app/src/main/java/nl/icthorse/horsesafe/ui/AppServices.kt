package nl.icthorse.horsesafe.ui

import nl.icthorse.horsesafe.flow.ChangePinFlow
import nl.icthorse.horsesafe.flow.EnvironmentProbe
import nl.icthorse.horsesafe.flow.FingerFlow
import nl.icthorse.horsesafe.flow.KeuringFlow
import nl.icthorse.horsesafe.flow.PracticeFlow
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.ReportFactory
import nl.icthorse.horsesafe.flow.SetupMachine
import nl.icthorse.horsesafe.flow.SetupMode
import nl.icthorse.horsesafe.report.ReportStore
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyDiscovery

/** Wat M12 over de vertrouwensankers toont. Geen geheimen. */
data class TrustInfo(
    val rootsSha256: String,
    val aaguidsSha256: String,
    val anchorCount: Int,
    val allowlistSize: Int,
    /** null = geladen en hash klopt; anders een Nederlandse foutmelding (fail-closed). */
    val error: String?,
)

/**
 * Wat de UI van de rest van de app nodig heeft. In de app levert `app/ServiceLocator` de echte
 * implementaties; tests leveren fakes.
 */
interface AppServices {
    val appVersion: String
    val isDebugBuild: Boolean
    val trust: TrustInfo
    val inspector: InspectorOps
    val reportFactory: ReportFactory
    val reports: ReportStore

    /**
     * keyId van de eigen app-sleutel voor de serial-HMAC (`SerialHasher.keyId`), of null als die niet
     * vast te stellen is. Bepaalt welk rapport voorrang krijgt als vergelijkingsbasis.
     */
    val serialKeyId: String? get() = null

    fun createSetupMachine(profile: Profile, mode: SetupMode): SetupMachine

    fun createDiscovery(): KeyDiscovery

    /** F4 (a)+(b). */
    fun keuringFlow(env: EnvironmentProbe): KeuringFlow

    /** F5. */
    fun changePinFlow(profile: Profile, env: EnvironmentProbe): ChangePinFlow

    /** F6 (alleen hoofdsleutel-Bio). */
    fun fingerFlow(env: EnvironmentProbe): FingerFlow

    /** F7. */
    fun practiceFlow(env: EnvironmentProbe): PracticeFlow = PracticeFlow(env)
}
