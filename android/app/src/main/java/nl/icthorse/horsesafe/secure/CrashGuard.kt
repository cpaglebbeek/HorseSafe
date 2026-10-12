package nl.icthorse.horsesafe.secure

import android.os.Process

/**
 * Eigen UncaughtExceptionHandler (plan, `HorseSafeApp`): wist alle geheimen en beëindigt het proces.
 *
 * Wat dit WEL en NIET voorkomt (review-bevinding, nagelezen in AOSP `RuntimeInit`):
 * - `Thread.dispatchUncaughtException` roept vóór deze handler altijd de pre-handler van het platform
 *   aan (`RuntimeInit.LoggingHandler`). Die schrijft "FATAL EXCEPTION" met het exceptiebericht en de
 *   stacktrace naar logcat `-b crash`. Dat kan een app niet uitzetten.
 * - Deze handler vervangt alleen de standaard-handler (`KillApplicationHandler`): daarmee gaat er geen
 *   crashrapport naar ActivityManager/dropbox (`data_app_crash`) en verschijnt er geen crashdialoog.
 * - Daarom geldt A-13 hard: geen exceptiebericht bevat ooit PIN- of tokendata (vaste teksten; de
 *   kanarietests controleren `Throwable.message`). En de ViewModel vangt fouten in zijn coroutines zelf
 *   af (event-lus en `runMaint`), zodat die de thread niet bereiken.
 *
 * Alleen het type van de fout en de stapnaam blijven in het geheugen ([lastCrash]); ze worden nergens
 * bewaard en verdwijnen met het proces.
 */
class CrashGuard internal constructor(
    private val kill: () -> Unit,
    private val stepName: () -> String?,
) : Thread.UncaughtExceptionHandler {

    override fun uncaughtException(t: Thread, e: Throwable) {
        try {
            lastCrash = CrashInfo(e.javaClass.simpleName.ifEmpty { "Throwable" }, safeStep())
            SecretRegistry.wipeAll()
        } catch (ignored: Throwable) {
            // niets wegschrijven
        } finally {
            kill()
        }
    }

    private fun safeStep(): String? = try {
        stepName()
    } catch (ignored: Throwable) {
        null
    }

    /** Alleen type en stapnaam; nooit het bericht of de stacktrace. */
    data class CrashInfo(val type: String, val step: String?)

    companion object {
        @Volatile
        var lastCrash: CrashInfo? = null
            internal set

        @Volatile
        private var installed = false

        /** Installeert de handler één keer per proces (idempotent). [stepName] = huidige stap, zonder geheim. */
        @Synchronized
        fun install(stepName: () -> String? = { null }) {
            if (installed) return
            Thread.setDefaultUncaughtExceptionHandler(
                CrashGuard(kill = { Process.killProcess(Process.myPid()) }, stepName = stepName),
            )
            installed = true
        }

        internal fun forTest(kill: () -> Unit, stepName: () -> String?) = CrashGuard(kill, stepName)
    }
}
