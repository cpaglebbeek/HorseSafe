package nl.icthorse.horsesafe.ui

import nl.icthorse.horsesafe.pin.CharSecretBuffer
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.SecretBuffer

/** M6 (hertypen tegen de gegenereerde PIN) of M8 (van papier, met controleteken per groep). */
enum class EntryMode { RETYPE, PAPER }

/**
 * Compose-veilige weergave van de invoer: alleen tellers en de status per groep, nooit tekens (A-11).
 */
data class EntryUi(
    val mode: EntryMode,
    /** Aantal goedgekeurde groepen (0..9); de groepen worden op volgorde ingevuld. */
    val groupsDone: Int,
    /** Getypte tekens in de huidige groep (0..7). */
    val typedInGroup: Int,
    /** PAPER: de 7 tekens zijn er, nu volgt het controleteken. */
    val awaitingCheck: Boolean,
    /** 1-based nummer van de laatst afgekeurde groep, of null. */
    val badGroup: Int?,
    /** RETYPE zonder groepscontrole: de app kan pas aan het eind zeggen of het klopt. */
    val groupCheckAvailable: Boolean,
) {
    val complete: Boolean get() = groupsDone == GroupCheck.GROUPS

    companion object {
        fun empty(mode: EntryMode, groupCheckAvailable: Boolean = true) =
            EntryUi(mode, 0, 0, awaitingCheck = false, badGroup = null, groupCheckAvailable = groupCheckAvailable)
    }
}

/**
 * Invoer van een PIN met het eigen toetsenblok (A-6). De tekens staan uitsluitend in een
 * [CharSecretBuffer]; een groep die niet klopt wordt meteen gewist en opnieuw gevraagd.
 *
 * - [EntryMode.PAPER]: per groep 7 tekens + het controleteken van het papier. Klopt het controleteken
 *   niet, dan "groep N klopt niet, controleer het papier" — dat kost geen poging op de sleutel (M8).
 * - [EntryMode.RETYPE]: per groep 7 tekens; [groupMatcher] vergelijkt in constante tijd met de
 *   gegenereerde PIN en zegt alleen of de groep klopt, nooit welk teken (M6).
 *
 * Het controleteken wordt na de controle direct gewist en nergens bewaard.
 */
class PinEntryController(
    val mode: EntryMode,
    private val groupMatcher: ((group: Int, typed: CharArray) -> Boolean)? = null,
) {
    private var buf: CharSecretBuffer? = CharSecretBuffer(SecretBuffer.PIN_LENGTH)
    private var groupsDone = 0
    private var inGroup = 0
    private var badGroup: Int? = null

    private val groupCheck: Boolean get() = mode == EntryMode.PAPER || groupMatcher != null

    var ui: EntryUi = EntryUi.empty(mode, groupCheck)
        private set

    val isWiped: Boolean get() = buf == null

    /** Eén toets. Tekens buiten het alfabet worden genegeerd. */
    fun key(c: Char): EntryUi {
        val b = buf ?: return ui
        if (groupsDone >= GroupCheck.GROUPS) return ui
        if (!nl.icthorse.horsesafe.pin.Alphabet.contains(c)) return ui
        if (inGroup < GroupCheck.GROUP_SIZE) {
            b.append(c)
            inGroup++
            badGroup = null
            if (inGroup == GroupCheck.GROUP_SIZE && mode == EntryMode.RETYPE) finishRetypeGroup(b)
        } else if (mode == EntryMode.PAPER) {
            finishPaperGroup(b, c)
        }
        return publish()
    }

    /** Wis: alleen binnen de huidige groep (afgekeurde of goedgekeurde groepen blijven zoals ze zijn). */
    fun delete(): EntryUi {
        val b = buf ?: return ui
        if (inGroup > 0 && groupsDone < GroupCheck.GROUPS) {
            b.removeLast()
            inGroup--
        }
        return publish()
    }

    /**
     * Geeft de volledige PIN over (eigendom gaat naar de ontvanger, die hem wist). Daarna is deze
     * controller leeg. null als de invoer niet compleet is.
     */
    fun take(): SecretBuffer? {
        val b = buf ?: return null
        if (groupsDone < GroupCheck.GROUPS || b.length != SecretBuffer.PIN_LENGTH) return null
        buf = null
        return b
    }

    /** Wist alles; idempotent. */
    fun wipe() {
        buf?.wipe()
        buf = null
        groupsDone = 0
        inGroup = 0
        ui = EntryUi.empty(mode, groupCheck)
    }

    private fun finishPaperGroup(b: CharSecretBuffer, check: Char) {
        val g = groupsDone
        val tmp = copyGroup(b, g)
        val ok = try {
            GroupCheck.verifyGroup(tmp, 0, check)
        } finally {
            tmp.fill('\u0000')
        }
        acceptOrReject(b, ok)
    }

    private fun finishRetypeGroup(b: CharSecretBuffer) {
        val matcher = groupMatcher
        if (matcher == null) {
            groupsDone++
            inGroup = 0
            return
        }
        val tmp = copyGroup(b, groupsDone)
        val ok = try {
            matcher(groupsDone, tmp)
        } finally {
            tmp.fill('\u0000')
        }
        acceptOrReject(b, ok)
    }

    private fun acceptOrReject(b: CharSecretBuffer, ok: Boolean) {
        if (ok) {
            groupsDone++
            badGroup = null
        } else {
            repeat(GroupCheck.GROUP_SIZE) { b.removeLast() }
            badGroup = groupsDone + 1
        }
        inGroup = 0
    }

    private fun copyGroup(b: CharSecretBuffer, group: Int): CharArray {
        val tmp = CharArray(GroupCheck.GROUP_SIZE)
        b.useChars { a -> System.arraycopy(a, group * GroupCheck.GROUP_SIZE, tmp, 0, GroupCheck.GROUP_SIZE) }
        return tmp
    }

    private fun publish(): EntryUi {
        ui = EntryUi(
            mode = mode,
            groupsDone = groupsDone,
            typedInGroup = inGroup,
            awaitingCheck = mode == EntryMode.PAPER && inGroup == GroupCheck.GROUP_SIZE,
            badGroup = badGroup,
            groupCheckAvailable = groupCheck,
        )
        return ui
    }

    override fun toString(): String = "PinEntryController(mode=$mode, groupsDone=$groupsDone)"
}
