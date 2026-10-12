package nl.icthorse.horsesafe.ui

import nl.icthorse.horsesafe.pin.Alphabet
import nl.icthorse.horsesafe.pin.GroupCheck
import nl.icthorse.horsesafe.pin.PinCompare
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.pin.RandomSource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PinEntryControllerTest {

    private val pinChars: CharArray = run {
        var i = 0
        val gen = PinGenerator(RandomSource { bound -> (i++ * 7 + 3) % bound })
        gen.generate().let { b -> b.useChars { it.copyOf() }.also { b.wipe() } }
    }

    private fun checkOf(g: Int): Char = GroupCheck.checkChar(pinChars, g * GroupCheck.GROUP_SIZE)

    private fun typeGroup(c: PinEntryController, g: Int, withCheck: Boolean, check: Char = checkOf(g)) {
        for (i in 0 until GroupCheck.GROUP_SIZE) c.key(pinChars[g * GroupCheck.GROUP_SIZE + i])
        if (withCheck) c.key(check)
    }

    @Test fun papierMetJuisteControletekensIsCompleet() {
        val c = PinEntryController(EntryMode.PAPER)
        for (g in 0 until GroupCheck.GROUPS) typeGroup(c, g, withCheck = true)
        assertTrue(c.ui.complete)
        val b = c.take()
        assertNotNull(b)
        b!!
        assertTrue(PinCompare.equal(b.useChars { it.copyOf() }, pinChars))
        assertTrue(c.isWiped)
        b.wipe()
    }

    @Test fun foutControletekenWistDeGroepEnKostNiets() {
        val c = PinEntryController(EntryMode.PAPER)
        typeGroup(c, 0, withCheck = true)
        val wrong = Alphabet.charAt((Alphabet.valueOf(checkOf(1)) + 1) % Alphabet.SIZE)
        typeGroup(c, 1, withCheck = true, check = wrong)
        assertEquals(1, c.ui.groupsDone)
        assertEquals(2, c.ui.badGroup)
        assertEquals(0, c.ui.typedInGroup)
        typeGroup(c, 1, withCheck = true)
        assertEquals(2, c.ui.groupsDone)
        assertNull(c.ui.badGroup)
        assertNull(c.take())
        c.wipe()
    }

    @Test fun controletekenWachtNaZevenTekens() {
        val c = PinEntryController(EntryMode.PAPER)
        for (i in 0 until 7) c.key(pinChars[i])
        assertTrue(c.ui.awaitingCheck)
        c.delete()
        assertFalse(c.ui.awaitingCheck)
        assertEquals(6, c.ui.typedInGroup)
    }

    @Test fun tekensBuitenHetAlfabetWordenGenegeerd() {
        val c = PinEntryController(EntryMode.PAPER)
        c.key('0'); c.key('l'); c.key('A')
        assertEquals(0, c.ui.typedInGroup)
    }

    @Test fun hertypenMetGroepscontrole() {
        val c = PinEntryController(EntryMode.RETYPE) { g, typed ->
            PinCompare.equal(pinChars.copyOfRange(g * 7, g * 7 + 7), typed)
        }
        typeGroup(c, 0, withCheck = false)
        assertEquals(1, c.ui.groupsDone)
        // groep 2 met één fout teken
        for (i in 0 until 6) c.key(pinChars[7 + i])
        c.key(Alphabet.charAt((Alphabet.valueOf(pinChars[13]) + 1) % Alphabet.SIZE))
        assertEquals(2, c.ui.badGroup)
        assertEquals(1, c.ui.groupsDone)
        for (g in 1 until 9) typeGroup(c, g, withCheck = false)
        assertTrue(c.ui.complete)
        assertTrue(c.ui.groupCheckAvailable)
        c.take()!!.wipe()
    }

    @Test fun hertypenZonderMatcherMeldtGeenGroepscontrole() {
        val c = PinEntryController(EntryMode.RETYPE, null)
        assertFalse(c.ui.groupCheckAvailable)
        for (g in 0 until 9) typeGroup(c, g, withCheck = false)
        assertTrue(c.ui.complete)
        c.wipe()
        assertTrue(c.isWiped)
        assertEquals(0, c.ui.groupsDone)
    }

    @Test fun uiStaatBevatGeenTekens() {
        val c = PinEntryController(EntryMode.PAPER)
        typeGroup(c, 0, withCheck = true)
        val text = c.ui.toString() + c.toString()
        val group = String(pinChars, 0, 7)
        assertFalse(text.contains(group))
        c.wipe()
    }
}
