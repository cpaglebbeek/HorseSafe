package nl.icthorse.horsesafe.app

import android.app.Activity
import android.content.Context
import java.lang.ref.WeakReference
import nl.icthorse.horsesafe.BuildConfig
import nl.icthorse.horsesafe.attest.AaguidAllowlist
import nl.icthorse.horsesafe.attest.AttestationResult
import nl.icthorse.horsesafe.attest.AttestationVerifier
import nl.icthorse.horsesafe.attest.TrustRoots
import nl.icthorse.horsesafe.flow.AttestOutcome
import nl.icthorse.horsesafe.flow.AttestationJudge
import nl.icthorse.horsesafe.flow.ChangePinFlow
import nl.icthorse.horsesafe.flow.DefaultSetupMachine
import nl.icthorse.horsesafe.flow.EnvironmentProbe
import nl.icthorse.horsesafe.flow.FingerFlow
import nl.icthorse.horsesafe.flow.KeuringFlow
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.ReportFactory
import nl.icthorse.horsesafe.flow.SetupMachine
import nl.icthorse.horsesafe.flow.SetupMode
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.report.AndroidKeystoreSerialKey
import nl.icthorse.horsesafe.report.ReportStore
import nl.icthorse.horsesafe.report.SerialHasher
import nl.icthorse.horsesafe.secure.EnvironmentGuard
import nl.icthorse.horsesafe.ui.AppServices
import nl.icthorse.horsesafe.ui.TrustInfo
import nl.icthorse.horsesafe.yubikey.Inspector
import nl.icthorse.horsesafe.yubikey.api.AttestOps
import nl.icthorse.horsesafe.yubikey.api.InspectorOps
import nl.icthorse.horsesafe.yubikey.api.KeyDiscovery
import nl.icthorse.horsesafe.yubikey.transport.YubiKitKeyDiscovery

/**
 * Eenvoudige ServiceLocator: koppelt de UI aan de echte implementaties van de andere modules.
 *
 * - Vertrouwensankers: de app-laag leest `assets/trust/…` en geeft de bytes plus de SHA-256 uit BuildConfig
 *   door aan `attest/` (kritiek 17). Mislukt dat, dan blijven roots en allowlist leeg: elke sleutel valt dan
 *   op AAGUID_NOT_ALLOWED of de attestation (fail-closed); M12 toont de fout.
 * - Serienummer: HMAC met een niet-exporteerbare sleutel in de Android Keystore (kritiek 8).
 * - Geen netwerk, geen logging.
 */
object ServiceLocator : AppServices {

    private lateinit var appContext: Context

    @Volatile
    private var activityRef: WeakReference<Activity>? = null

    fun init(context: Context) {
        if (!::appContext.isInitialized) appContext = context.applicationContext
    }

    /** De actieve activity (voor NFC-foreground-dispatch); zwak vastgehouden. */
    fun setActivity(activity: Activity?) {
        activityRef = activity?.let { WeakReference(it) }
    }

    private fun currentActivity(): Activity? = activityRef?.get()

    override val appVersion: String get() = BuildConfig.VERSION_NAME

    private class Anchors(val roots: TrustRoots, val allowlist: AaguidAllowlist, val error: String?)

    private val anchors: Anchors by lazy { loadAnchors() }

    private fun loadAnchors(): Anchors {
        var error: String? = null
        val roots = try {
            TrustRoots.fromPem(readAsset(ROOTS_ASSET), BuildConfig.TRUST_ROOTS_SHA256)
        } catch (e: Exception) {
            error = "De Yubico-roots konden niet worden geladen."
            TrustRoots.EMPTY
        }
        val allow = try {
            AaguidAllowlist.fromJson(readAsset(AAGUIDS_ASSET), BuildConfig.AAGUIDS_SHA256)
        } catch (e: Exception) {
            error = (error?.plus(" ") ?: "") + "De AAGUID-lijst kon niet worden geladen."
            AaguidAllowlist.EMPTY
        }
        return Anchors(roots, allow, error)
    }

    private fun readAsset(name: String): ByteArray = appContext.assets.open(name).use { it.readBytes() }

    override val trust: TrustInfo by lazy {
        val a = anchors
        TrustInfo(
            rootsSha256 = BuildConfig.TRUST_ROOTS_SHA256,
            aaguidsSha256 = BuildConfig.AAGUIDS_SHA256,
            anchorCount = a.roots.anchors.size,
            allowlistSize = a.allowlist.size,
            error = a.error,
        )
    }

    private val verifier: AttestationVerifier by lazy { AttestationVerifier(anchors.roots, anchors.allowlist) }

    /** Brug van `attest/AttestationVerifier` naar het flow-contract [AttestationJudge]. */
    private val judge: AttestationJudge by lazy {
        AttestationJudge { evidence, expected ->
            if (expected.rpId != AttestOps.KEURING_RP_ID) {
                AttestOutcome.Failed(Stop.ATTEST_RP_ID_HASH)
            } else {
                when (val r = verifier.verify(evidence, expected.aaguid, expected.keyClass)) {
                    is AttestationResult.Ok ->
                        if (expected.requireUv && !r.userVerified) AttestOutcome.Failed(Stop.ATTEST_FLAGS_INVALID)
                        else AttestOutcome.Ok(r.leafSha256)
                    is AttestationResult.Failed -> AttestOutcome.Failed(r.stop)
                }
            }
        }
    }

    private val serialHasher: SerialHasher by lazy { SerialHasher(AndroidKeystoreSerialKey()) }

    override val inspector: InspectorOps by lazy {
        Inspector(
            aaguids = anchors.allowlist,
            serialHasher = nl.icthorse.horsesafe.yubikey.SerialHasher { serial ->
                serialHasher.hash(serial) ?: error("geen serienummer")
            },
        )
    }

    override val serialKeyId: String?
        get() = try {
            serialHasher.keyId
        } catch (e: Exception) {
            null
        }

    override val reportFactory: ReportFactory by lazy { ReportFactory(appVersion) }

    override val reports: ReportStore by lazy { ReportStore.forContext(appContext) }

    override fun createSetupMachine(profile: Profile, mode: SetupMode): SetupMachine =
        DefaultSetupMachine(profile, mode, inspector, judge, reportFactory)

    override fun keuringFlow(env: EnvironmentProbe): KeuringFlow = KeuringFlow(inspector, judge, reportFactory, env)

    override fun changePinFlow(profile: Profile, env: EnvironmentProbe): ChangePinFlow =
        ChangePinFlow(profile, inspector, reportFactory, env = env)

    override fun fingerFlow(env: EnvironmentProbe): FingerFlow =
        FingerFlow(inspector, reportFactory, env, knownProfileOf = { serial -> reports.profileForSerial(serial) })

    override fun createDiscovery(): KeyDiscovery = YubiKitKeyDiscovery(appContext, { currentActivity() })

    /** Release: ADB aan = STOP vóór de PIN-schermen; debug: alleen waarschuwing. */
    val environmentGuard: EnvironmentGuard by lazy { EnvironmentGuard(adbIsStop = !BuildConfig.DEBUG) }

    override val isDebugBuild: Boolean get() = BuildConfig.DEBUG

    private const val ROOTS_ASSET = "trust/yubico_fido_roots.pem"
    private const val AAGUIDS_ASSET = "trust/aaguids.json"
}
