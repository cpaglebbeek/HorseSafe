package nl.icthorse.horsesafe.secure

import android.app.Activity
import android.os.Process

/**
 * Beëindigt de app volledig (A-12): eerst alle geheimen wissen, dan de taak uit "recent" halen en het
 * proces stoppen, zodat ook de kopieën in de yubikit-heap (B-17) verdwijnen.
 */
object ProcessEnd {
    /** Te vervangen in tests; standaard `Process.killProcess(myPid())`. */
    @Volatile
    internal var killer: () -> Unit = { Process.killProcess(Process.myPid()) }

    fun end(activity: Activity?) {
        SecretRegistry.wipeAll()
        try {
            activity?.finishAndRemoveTask()
        } catch (t: Throwable) {
            // doorgaan
        }
        killer()
    }
}
