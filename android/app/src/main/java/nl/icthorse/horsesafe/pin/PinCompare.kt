package nl.icthorse.horsesafe.pin

/**
 * Vergelijken van geheimen in constante tijd: altijd alle posities tot de grootste lengte, zonder
 * vroeg te stoppen bij het eerste verschil. Alleen de (niet-geheime) lengtes bepalen het aantal stappen.
 */
object PinCompare {

    fun equal(a: SecretBuffer, b: SecretBuffer): Boolean {
        val la = a.length
        val lb = b.length
        val n = maxOf(la, lb)
        var diff = la xor lb
        for (i in 0 until n) {
            val x = if (i < la) a[i].code else 0
            val y = if (i < lb) b[i].code else 0
            diff = diff or (x xor y)
        }
        return diff == 0
    }

    fun equal(a: CharArray, b: CharArray): Boolean {
        val n = maxOf(a.size, b.size)
        var diff = a.size xor b.size
        for (i in 0 until n) {
            val x = if (i < a.size) a[i].code else 0
            val y = if (i < b.size) b[i].code else 0
            diff = diff or (x xor y)
        }
        return diff == 0
    }
}
