package nl.icthorse.horsesafe.pin

/**
 * Geheim (PIN) uitsluitend als CharArray met vaste capaciteit (63 bij HorseSafe, A-11/A-20).
 * Nooit omzetten naar String, nooit in Compose-state, Bundle of SavedStateHandle.
 *
 * Contract voor implementaties:
 * - [toString] geeft altijd exact [HIDDEN] terug ("[verborgen]");
 * - [wipe] overschrijft de hele array (`fill('\u0000')`), is idempotent en zet [length] op 0;
 * - na [wipe] gooit elke lees- of schrijfactie [IllegalStateException];
 * - `equals` is identiteit; vergelijken van inhoud gaat alleen via `pin/PinCompare` (constante tijd).
 */
interface SecretBuffer : AutoCloseable {
    /** Maximale lengte (63). */
    val capacity: Int

    /** Aantal ingevulde tekens. */
    val length: Int

    val isWiped: Boolean

    /** Voegt één teken toe; [IllegalStateException] als de buffer vol of gewist is. */
    fun append(c: Char)

    /** Verwijdert het laatste teken (en overschrijft die positie). */
    fun removeLast()

    /** Teken op positie [index] (0-based, < [length]). */
    operator fun get(index: Int): Char

    /**
     * Leent de onderliggende CharArray (precies [length] geldig) aan [block], bv. voor yubikit
     * `ClientPin.setPin(char[])` of `Canvas.drawText(char[], …)`. [block] mag de array niet bewaren.
     */
    fun <T> useChars(block: (CharArray) -> T): T

    /** Overschrijft de inhoud met nullen. */
    fun wipe()

    override fun close() = wipe()

    /** Moet [HIDDEN] teruggeven. */
    override fun toString(): String

    companion object {
        const val HIDDEN: String = "[verborgen]"
        const val PIN_LENGTH: Int = 63
    }
}
