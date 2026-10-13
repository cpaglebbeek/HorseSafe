package nl.icthorse.horsesafe.yubikey

import com.yubico.yubikit.core.fido.CtapException
import nl.icthorse.horsesafe.yubikey.api.KeyError
import nl.icthorse.horsesafe.yubikey.api.ResetOps

/**
 * [ResetOps] op yubikit 3.0.1 `Ctap2Session.reset(CommandState)`. Het enige bestand in de app dat de
 * reset aanroept (bewaakt door YubikeyFlowSourcePolicyTest).
 *
 * NOT_ALLOWED (0x30) betekent bij reset: buiten het venster na insteken → [KeyError.ResetWindowPassed]
 * (in [KeyErrors] valt 0x30 anders samen met OPERATION_DENIED). Na de reset een verse getInfo.
 */
internal class YubikitResetOps(private val phase: YubikitCtapPhase) : ResetOps {
    override suspend fun wipeFido() {
        val state = phase.beginCommand()
        try {
            phase.call {
                try {
                    phase.session.reset(state)
                } catch (e: CtapException) {
                    val code = e.ctapError.toInt() and 0xFF
                    throw if (code == NOT_ALLOWED) KeyError.ResetWindowPassed() else KeyErrors.fromCtap(code)
                }
            }
        } finally {
            phase.endCommand(state)
        }
        phase.refresh()
    }

    private companion object {
        const val NOT_ALLOWED = 0x30
    }
}
