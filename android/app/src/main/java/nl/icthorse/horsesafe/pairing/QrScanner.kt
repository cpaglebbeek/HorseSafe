package nl.icthorse.horsesafe.pairing

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import com.google.zxing.BarcodeFormat
import com.google.zxing.ResultPoint
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.BarcodeView
import com.journeyapps.barcodescanner.DefaultDecoderFactory

/**
 * QR-scanner (zxing-android-embedded, zonder GMS) als view in het eigen venster: geen aparte
 * scan-activity, dus FLAG_SECURE blijft gelden. Het camerabeeld loopt via een TextureView (geen
 * SurfaceView), zodat het in het beveiligde venster wordt getekend. Alleen QR-codes.
 *
 * De camera loopt alleen zolang deze composable in beeld is (resume bij binnenkomst, pause bij weggaan);
 * de app vraagt CAMERA pas vlak voor het scannen.
 */
@Composable
fun QrScanner(modifier: Modifier, onText: (String) -> Unit) {
    val context = LocalContext.current
    val callback by rememberUpdatedState(onText)
    val view = remember {
        BarcodeView(context).apply {
            setUseTextureView(true)
            decoderFactory = DefaultDecoderFactory(listOf(BarcodeFormat.QR_CODE))
        }
    }
    DisposableEffect(view) {
        view.decodeContinuous(object : BarcodeCallback {
            override fun barcodeResult(result: BarcodeResult) {
                result.text?.let { callback(it) }
            }

            override fun possibleResultPoints(resultPoints: MutableList<ResultPoint>) = Unit
        })
        view.resume()
        onDispose {
            view.stopDecoding()
            view.pause()
        }
    }
    AndroidView(factory = { view }, modifier = modifier)
}
