package nl.icthorse.horsesafe.app

import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.os.Bundle
import android.view.KeyEvent
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import java.security.MessageDigest
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import nl.icthorse.horsesafe.report.ReportStore
import nl.icthorse.horsesafe.secure.CrashGuard
import nl.icthorse.horsesafe.secure.ProcessEnd
import nl.icthorse.horsesafe.secure.ScreenWatch
import nl.icthorse.horsesafe.secure.SecureWindow
import nl.icthorse.horsesafe.ui.HorseSafeRoot
import nl.icthorse.horsesafe.ui.HorseSafeViewModel
import nl.icthorse.horsesafe.ui.PairingViewModel
import nl.icthorse.horsesafe.ui.RootActions

/**
 * Enige activity van HorseSafe (Compose).
 *
 * - Vensterregels vóór `setContent` (A-1..A-3, A-7, A-9) via [SecureWindow]; schermopname via [ScreenWatch].
 * - Eigen UncaughtExceptionHandler ([CrashGuard]): wist geheimen, schrijft niets, beëindigt het proces.
 * - Omgeving ([nl.icthorse.horsesafe.secure.EnvironmentGuard]) bij elke hervatting, focuswissel,
 *   multi-window- of configuratiewissel en opname-melding.
 * - "Afsluiten" en het einde van een inrichting: [ProcessEnd] (finishAndRemoveTask + killProcess).
 * - Deel 2: FragmentActivity (de systeem-vingerprompt van androidx.biometric heeft er een nodig);
 *   "Telefoon koppelen" heeft een eigen [PairingViewModel].
 */
class MainActivity : FragmentActivity() {

    private lateinit var vm: HorseSafeViewModel
    private lateinit var pairing: PairingViewModel
    private val screenWatch = ScreenWatch()

    private val exportLauncher = registerForActivityResult(ActivityResultContracts.CreateDocument(ReportStore.MIME_TYPE)) { uri ->
        if (uri != null) vm.export(contentResolver, uri)
    }

    private val importLauncher = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) vm.import(contentResolver, uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        SecureWindow.beforeContent(this)
        CrashGuard.install { if (::vm.isInitialized) vm.ui.value.screen.code else null }
        super.onCreate(savedInstanceState)
        ServiceLocator.init(this)
        ServiceLocator.setActivity(this)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        vm = ViewModelProvider(this, HorseSafeViewModel.factory(ServiceLocator))[HorseSafeViewModel::class.java]
        pairing = ViewModelProvider(this, PairingViewModel.factory(ServiceLocator.pairing))[PairingViewModel::class.java]
        val signer = signerSha256()

        setContent {
            HorseSafeRoot(
                vm = vm,
                pairing = pairing,
                services = ServiceLocator,
                signerSha256 = signer,
                actions = RootActions(
                    export = { vm.ui.value.report?.let { exportLauncher.launch(ReportStore.suggestedFileName(it)) } },
                    import = { importLauncher.launch(arrayOf(ReportStore.MIME_TYPE, "application/octet-stream", "text/plain")) },
                ),
            )
        }
        SecureWindow.onContentSet(this)

        lifecycleScope.launch {
            vm.ui.map { it.quit }.distinctUntilChanged().collect { quit -> if (quit) ProcessEnd.end(this@MainActivity) }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    // A-3 (API 34+): melding bij een schermafbeelding; de ingedrukte PIN-groep gaat dicht.
                    var seen = screenWatch.captureCount.value
                    screenWatch.captureCount.collect { n ->
                        if (n > seen) vm.onScreenCaptured()
                        seen = n
                    }
                }
                screenWatch.recording.collect { rec ->
                    if (rec) vm.setWindowVisible(false)
                    checkEnvironment()
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        ServiceLocator.setActivity(this)
        screenWatch.start(this)
        checkEnvironment()
        vm.onStart()
    }

    override fun onResume() {
        super.onResume()
        checkEnvironment()
        vm.setWindowVisible(hasWindowFocus() && !screenWatch.recording.value)
    }

    override fun onPause() {
        vm.setWindowVisible(false)
        super.onPause()
    }

    override fun onStop() {
        vm.onStop()
        pairing.onStop()
        screenWatch.stop(this)
        super.onStop()
    }

    override fun onDestroy() {
        ServiceLocator.setActivity(null)
        super.onDestroy()
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        vm.setWindowVisible(hasFocus && !screenWatch.recording.value)
        if (hasFocus) checkEnvironment()
    }

    override fun onMultiWindowModeChanged(isInMultiWindowMode: Boolean, newConfig: Configuration) {
        super.onMultiWindowModeChanged(isInMultiWindowMode, newConfig)
        checkEnvironment()
    }

    override fun onPictureInPictureModeChanged(isInPictureInPictureMode: Boolean, newConfig: Configuration) {
        super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig)
        checkEnvironment()
    }

    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        checkEnvironment()
    }

    /**
     * A-6: op schermen met een geheim (M4, M5, M6, M8) geen invoer via een hardwaretoetsenbord. Een
     * HID-toetsenbord (of een YubiKey 5 met OTP aan, die modhex plus Enter typt) zou anders met Tab,
     * pijltjes en Enter knoppen kunnen activeren. Alleen Terug en volume komen door.
     *
     * RestrictedApi is hier een vals alarm: `androidx.core.app.ComponentActivity` markeert zijn override
     * van de publieke `Activity.dispatchKeyEvent` als @RestrictTo; wij overschrijven de platform-API.
     */
    @SuppressLint("RestrictedApi")
    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        if (::vm.isInitialized && vm.ui.value.screen.holdsSecret && !keyAllowedOnSecretScreen(event.keyCode)) return true
        return super.dispatchKeyEvent(event)
    }

    @SuppressLint("RestrictedApi")
    override fun dispatchKeyShortcutEvent(event: KeyEvent): Boolean {
        if (::vm.isInitialized && vm.ui.value.screen.holdsSecret) return true
        return super.dispatchKeyShortcutEvent(event)
    }

    private fun checkEnvironment() {
        if (!::vm.isInitialized) return
        val report = try {
            ServiceLocator.environmentGuard.check(this, screenWatch.recording.value)
        } catch (e: RuntimeException) {
            null
        }
        if (report != null) vm.onEnvironment(report)
    }

    private fun keyAllowedOnSecretScreen(code: Int): Boolean = code == KeyEvent.KEYCODE_BACK ||
        code == KeyEvent.KEYCODE_VOLUME_UP || code == KeyEvent.KEYCODE_VOLUME_DOWN || code == KeyEvent.KEYCODE_VOLUME_MUTE

    /** SHA-256 van het ondertekeningscertificaat, voor M12. */
    private fun signerSha256(): String? = try {
        val info = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        val cert = info.signingInfo?.apkContentsSigners?.firstOrNull()?.toByteArray()
        cert?.let { MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { b -> "%02x".format(b) } }
    } catch (e: Exception) {
        null
    }
}
