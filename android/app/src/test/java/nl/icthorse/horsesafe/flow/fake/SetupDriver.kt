package nl.icthorse.horsesafe.flow.fake

import nl.icthorse.horsesafe.flow.DefaultSetupMachine
import nl.icthorse.horsesafe.flow.FlowEvent
import nl.icthorse.horsesafe.flow.MaxPinLengthPolicy
import nl.icthorse.horsesafe.flow.Profile
import nl.icthorse.horsesafe.flow.SetupMode
import nl.icthorse.horsesafe.flow.State
import nl.icthorse.horsesafe.flow.Stop
import nl.icthorse.horsesafe.pin.CharSecretBuffer
import nl.icthorse.horsesafe.pin.PinGenerator
import nl.icthorse.horsesafe.pin.RandomSource
import nl.icthorse.horsesafe.pin.SecretBuffer

/** Vaste PIN-bron: cyclisch door [values] (indexen in het alfabet). */
class CyclicSource(private val values: IntArray) : RandomSource {
    private var i = 0
    override fun nextInt(bound: Int): Int = values[i++ % values.size] % bound
}

/** Bedient een [DefaultSetupMachine] zoals de UI dat doet; [paper] = wat Christian overschrijft. */
class SetupDriver(
    val key: FakeYubiKey,
    val profile: Profile,
    val mode: SetupMode = SetupMode.NEW,
    policy: MaxPinLengthPolicy = MaxPinLengthPolicy.ASSUME_CTAP21_MAX,
    source: RandomSource = CyclicSource(intArrayOf(9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 3, 5, 7)),
) {
    val machine = DefaultSetupMachine(
        profile, mode, KeyProfiles.inspector(), FakeAttestationJudge, KeyProfiles.reports(),
        PinGenerator(source), policy,
    )

    /** Het "papier": kopie van de gegenereerde PIN (alleen in de test). */
    var paper: CharArray? = null

    val state: State get() = machine.state.value

    suspend fun send(e: FlowEvent): State = machine.handle(e)

    suspend fun detect(violations: List<Stop> = emptyList()): State {
        send(FlowEvent.EnvironmentChecked(violations))
        return send(FlowEvent.KeyConnected(key))
    }

    /** M3 → M4 (papier overschrijven) → M5 (alle 9 groepen hertypen). */
    suspend fun pinUntilRetyped(): State {
        send(FlowEvent.ChecklistConfirmed)
        if (state !is State.PinGenerated) return state
        paper = machine.revealPin { b -> b.useChars { it.copyOf() } }
        send(FlowEvent.RevealFinished)
        return send(FlowEvent.PinRetyped(bufferOf(paper!!)))
    }

    suspend fun confirmIrreversible(): State = send(FlowEvent.IrreversibleConfirmed)

    suspend fun fingers(vararg names: String): State {
        names.forEach { send(FlowEvent.EnrollFinger(it)) }
        return send(FlowEvent.FingersDone)
    }

    /** Volledige nieuwe inrichting tot ReportReady (of eerder gestopt). */
    suspend fun runNew(vararg fingerNames: String = arrayOf("R-wijs", "L-wijs")): State {
        detect()
        if (state is State.Stopped) return state
        pinUntilRetyped()
        if (state is State.Stopped) return state
        confirmIrreversible()
        if (state is State.Stopped || profile != Profile.BIO_MAIN) return state
        return fingers(*fingerNames)
    }

    /** Hervatten met de PIN van papier. */
    suspend fun runResume(paper: CharArray, vararg fingerNames: String = arrayOf("R-wijs", "L-wijs")): State {
        detect()
        if (state !is State.GateResumeOk) return state
        send(FlowEvent.ChecklistConfirmed)
        send(FlowEvent.PinEntered(bufferOf(paper)))
        if (state is State.CountsOk) confirmIrreversible()
        if (state is State.Stopped || profile != Profile.BIO_MAIN) return state
        val have = machine.fingers.value.size
        val add = fingerNames.drop(have).take((2 - have).coerceAtLeast(0))
        return fingers(*add.toTypedArray())
    }

    companion object {
        fun bufferOf(chars: CharArray): SecretBuffer = CharSecretBuffer().also { b -> chars.forEach { b.append(it) } }
    }
}
