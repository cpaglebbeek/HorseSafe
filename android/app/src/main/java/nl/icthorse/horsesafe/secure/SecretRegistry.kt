package nl.icthorse.horsesafe.secure

import java.util.concurrent.CopyOnWriteArrayList

/**
 * Centrale wisknop: elke houder van een geheim (ViewModel, SetupMachine, invoerbuffers) meldt hier een
 * wisfunctie aan. [ProcessEnd] en [CrashGuard] roepen [wipeAll] aan vóór het proces stopt.
 * Bewaart zelf geen geheim, alleen functies.
 */
object SecretRegistry {
    private val wipers = CopyOnWriteArrayList<() -> Unit>()

    /** @return een handle om weer af te melden. */
    fun register(wiper: () -> Unit): AutoCloseable {
        wipers += wiper
        return AutoCloseable { wipers.remove(wiper) }
    }

    /** Roept elke wisfunctie aan; een fout in één wisser stopt de andere niet en wordt niet gelogd. */
    fun wipeAll() {
        for (w in wipers) {
            try {
                w()
            } catch (t: Throwable) {
                // bewust stil: geen details wegschrijven (A-13)
            }
        }
    }

    internal fun size(): Int = wipers.size

    internal fun clearForTest() = wipers.clear()
}
