package nl.icthorse.horsesafe.secure

import android.app.Activity
import androidx.annotation.RequiresApi
import android.os.Build
import android.view.View
import android.view.WindowManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.function.Consumer

/**
 * Vensterregels A-1..A-4, A-7 en A-9.
 *
 * - [beforeContent] in `onCreate` VÓÓR `super.onCreate`/`setContent`: FLAG_SECURE, geen
 *   recents-screenshot, overlays van andere apps verbergen.
 * - [onContentSet] direct na `setContent`: op de root-view `filterTouchesWhenObscured`,
 *   autofill en content capture uit voor de hele boom, en (API 34+) `accessibilityDataSensitive`.
 * - [ScreenWatch] meldt schermopname (API 35) en schermafbeeldingen (API 34).
 */
object SecureWindow {

    fun beforeContent(activity: Activity) {
        val w = activity.window
        w.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        activity.setRecentsScreenshotEnabled(false)
        // HIDE_OVERLAY_WINDOWS-permissie staat in het manifest (A-2).
        w.setHideOverlayWindows(true)
    }

    fun onContentSet(activity: Activity) {
        val root: View = activity.window.decorView
        protectView(root)
        activity.findViewById<View>(android.R.id.content)?.let { content ->
            protectView(content)
            (content as? android.view.ViewGroup)?.let { g -> for (i in 0 until g.childCount) protectView(g.getChildAt(i)) }
        }
    }

    /** Ook bruikbaar voor de ComposeView zelf. */
    fun protectView(v: View) {
        v.filterTouchesWhenObscured = true
        v.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        v.importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            v.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
    }

    /** true als FLAG_SECURE op het venster staat (voor tests en M12). */
    fun isSecure(activity: Activity): Boolean =
        (activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
}

/**
 * Bewaakt schermopname en schermafbeeldingen (A-3). Registreren in `onStart`, afmelden in `onStop`.
 * - [recording] true = het venster wordt opgenomen (API 35 `addScreenRecordingCallback`); de PIN gaat dicht.
 * - [captureCount] telt gemelde schermafbeeldingen (API 34 `ScreenCaptureCallback`); FLAG_SECURE maakt
 *   ze zwart, de UI toont een melding.
 */
class ScreenWatch {
    private val _recording = MutableStateFlow(false)
    val recording: StateFlow<Boolean> = _recording.asStateFlow()

    private val _captureCount = MutableStateFlow(0)
    val captureCount: StateFlow<Int> = _captureCount.asStateFlow()

    private var recordingCallback: Consumer<Int>? = null
    private var captureCallback: Any? = null

    fun start(activity: Activity) {
        if (Build.VERSION.SDK_INT >= 35) startRecording(activity)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) startCapture(activity)
    }

    fun stop(activity: Activity) {
        if (Build.VERSION.SDK_INT >= 35) stopRecording(activity)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) stopCapture(activity)
    }

    @RequiresApi(35)
    private fun startRecording(activity: Activity) {
        if (recordingCallback != null) return
        val cb = Consumer<Int> { state -> _recording.value = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE }
        try {
            val initial = activity.windowManager.addScreenRecordingCallback(activity.mainExecutor, cb)
            _recording.value = initial == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
            recordingCallback = cb
        } catch (e: SecurityException) {
            // Permissie ontbreekt: fail-closed niet mogelijk zonder melding; behandel als "onbekend" = niet opgenomen.
            recordingCallback = null
        }
    }

    @RequiresApi(35)
    private fun stopRecording(activity: Activity) {
        val cb = recordingCallback ?: return
        try {
            activity.windowManager.removeScreenRecordingCallback(cb)
        } catch (e: RuntimeException) {
            // al afgemeld
        }
        recordingCallback = null
        _recording.value = false
    }

    @RequiresApi(34)
    private fun startCapture(activity: Activity) {
        if (captureCallback != null) return
        val cb = Activity.ScreenCaptureCallback { _captureCount.value = _captureCount.value + 1 }
        try {
            activity.registerScreenCaptureCallback(activity.mainExecutor, cb)
            captureCallback = cb
        } catch (e: SecurityException) {
            captureCallback = null
        }
    }

    @RequiresApi(34)
    private fun stopCapture(activity: Activity) {
        val cb = captureCallback as? Activity.ScreenCaptureCallback ?: return
        try {
            activity.unregisterScreenCaptureCallback(cb)
        } catch (e: RuntimeException) {
            // al afgemeld
        }
        captureCallback = null
    }
}
