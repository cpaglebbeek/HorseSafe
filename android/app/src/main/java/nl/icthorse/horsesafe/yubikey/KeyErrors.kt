package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.application.ApplicationNotAvailableException
import com.yubico.yubikit.core.application.BadResponseException
import com.yubico.yubikit.core.application.TimeoutException
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.core.smartcard.ApduException
import java.io.IOException
import java.nio.BufferUnderflowException
import kotlin.coroutines.cancellation.CancellationException
import nl.icthorse.horsesafe.yubikey.api.KeyError

/**
 * Vertaalt yubikit- en JVM-excepties naar [KeyError] (contract KeyError.kt).
 *
 * Regels (A-13):
 * - de oorspronkelijke exceptie gaat NOOIT als `cause` mee en haar bericht wordt niet overgenomen
 *   (yubikit-berichten kunnen hex van APDU's of HID-pakketten bevatten);
 * - [CancellationException] wordt nooit vertaald maar doorgegooid (coroutine-semantiek);
 * - een al vertaalde [KeyError] blijft ongewijzigd.
 */
internal object KeyErrors {

    /**
     * @param disconnected true als de link al weet dat de sleutel weg is; een I/O-fout wordt dan
     *   [KeyError.Disconnected] in plaats van [KeyError.Io].
     */
    fun map(t: Throwable, disconnected: Boolean = false): Throwable = when (t) {
        is CancellationException -> t
        is KeyError -> t
        is NestedConnectionError -> t
        is CtapException -> fromCtap(t.ctapError.toInt() and 0xFF)
        is TimeoutException -> KeyError.UserActionTimeout()
        is ApplicationNotAvailableException -> KeyError.NotSupported("applet")
        is ApduException -> KeyError.Protocol("apdu-status")
        is BadResponseException -> KeyError.Protocol("antwoord")
        is IOException -> when {
            disconnected || isTagLost(t) -> KeyError.Disconnected()
            else -> KeyError.Io(t.javaClass.simpleName.ifEmpty { "IOException" })
        }
        is UnsupportedOperationException -> KeyError.NotSupported("functie")
        // yubikit gooit IllegalStateException("Not supported") als een functie volgens de (in de
        // sessie gecachete) getInfo ontbreekt. De adapters controleren dat vooraf op een verse
        // getInfo; wat hier nog binnenkomt is een onverwachte toestand.
        is IllegalStateException -> KeyError.Protocol("toestand")
        // Cbor.decode (IllegalArgumentException/BufferUnderflow), casts en requireNonNull op
        // ontbrekende velden in een antwoord.
        is IllegalArgumentException, is BufferUnderflowException, is ClassCastException,
        is NullPointerException, is IndexOutOfBoundsException -> KeyError.Protocol("cbor")
        else -> KeyError.Protocol(t.javaClass.simpleName.ifEmpty { "onbekend" })
    }

    /** CTAP 2.1-statuscode → [KeyError]. Pogingen ([KeyError.PinInvalid.retriesLeft]) vult de aanroeper. */
    fun fromCtap(code: Int): KeyError = when (code) {
        0x31 -> KeyError.PinInvalid(null)                 // PIN_INVALID
        0x32 -> KeyError.PinBlocked()                     // PIN_BLOCKED
        0x33 -> KeyError.TokenInvalid()                   // PIN_AUTH_INVALID (verkeerde/verlopen token-MAC)
        0x34 -> KeyError.PinAuthBlocked()                 // PIN_AUTH_BLOCKED
        0x35 -> KeyError.PinNotSet()                      // PIN_NOT_SET
        0x36 -> KeyError.PinUvAuthTokenRequired()         // PUAT_REQUIRED
        0x37 -> KeyError.PinPolicyViolation()             // PIN_POLICY_VIOLATION
        0x38 -> KeyError.TokenInvalid()                   // PIN_TOKEN_EXPIRED
        0x40 -> KeyError.TokenInvalid()                   // UNAUTHORIZED_PERMISSION
        0x3F -> KeyError.UvInvalid(null)                  // UV_INVALID
        0x3C -> KeyError.UvBlocked()                      // UV_BLOCKED
        0x27, 0x30 -> KeyError.OperationDenied()          // OPERATION_DENIED, NOT_ALLOWED
        0x2F, 0x3A, 0x05, 0x2D -> KeyError.UserActionTimeout() // USER_ACTION_TIMEOUT, ACTION_TIMEOUT, TIMEOUT, KEEPALIVE_CANCEL
        0x01, 0x3E -> KeyError.NotSupported("ctap-commando") // INVALID_COMMAND, INVALID_SUBCOMMAND
        else -> KeyError.Ctap(code)
    }

    /** android.nfc.TagLostException is een IOException; op naam herkend (geen Android-klasse in JVM-tests). */
    private fun isTagLost(e: IOException): Boolean = e.javaClass.simpleName == "TagLostException"
}

/**
 * Voert een blokkerende yubikit-aanroep uit en vertaalt elke fout via [KeyErrors.map].
 * Alleen voor code die op de verbindingsthread draait (binnen `requestConnection`).
 */
internal inline fun <T> keyCall(disconnected: () -> Boolean = { false }, block: () -> T): T =
    try {
        block()
    } catch (t: Throwable) {
        throw KeyErrors.map(t, disconnected())
    }

/** Programmeerfout: een verbinding openen binnen een open verbinding (zou op USB vastlopen). */
class NestedConnectionError : IllegalStateException("geneste of gelijktijdige sleutelverbinding")
