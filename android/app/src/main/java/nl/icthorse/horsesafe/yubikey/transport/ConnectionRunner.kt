package nl.icthorse.horsesafe.yubikey.transport

import com.yubico.yubikit.core.YubiKeyConnection
import com.yubico.yubikit.core.YubiKeyDevice
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.cancellation.CancellationException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.suspendCancellableCoroutine
import nl.icthorse.horsesafe.yubikey.CancelSignal
import nl.icthorse.horsesafe.yubikey.KeyErrors
import nl.icthorse.horsesafe.yubikey.NestedConnectionError
import nl.icthorse.horsesafe.yubikey.api.KeyError

/**
 * Opent één verbinding van type [C], voert [block] daarin uit en sluit de verbinding weer.
 * Elke aanroep = een eigen verbinding (kritiek 22).
 */
interface ConnectionRunner {
    suspend fun <C : YubiKeyConnection, R> withConnection(
        type: Class<C>,
        cancel: CancelSignal,
        block: suspend (C) -> R,
    ): R
}

/**
 * [ConnectionRunner] op `YubiKeyDevice.requestConnection` (yubikit 3.0.1).
 *
 * yubikit roept de callback aan op zijn eigen executorthread (USB: één thread per apparaat, dus alle
 * verbindingen naar één sleutel lopen na elkaar) en sluit de verbinding zodra de callback terugkeert.
 * Daarom draait [block] BINNEN de callback, met `runBlocking` op die achtergrondthread (nooit de
 * main thread). Annuleren van de aanroepende coroutine:
 * - zet [CancelSignal] (de lopende yubikit-`CommandState` stuurt CTAP-cancel), en
 * - annuleert de binnenste coroutine.
 *
 * Een geneste aanroep (verbinding openen binnen een open verbinding) zou op USB vastlopen op de
 * ene executorthread en wordt daarom geweigerd met [NestedConnectionError].
 */
internal class DeviceConnectionRunner(
    private val device: YubiKeyDevice,
    private val disconnected: () -> Boolean,
) : ConnectionRunner {

    private val busy = AtomicBoolean(false)

    override suspend fun <C : YubiKeyConnection, R> withConnection(
        type: Class<C>,
        cancel: CancelSignal,
        block: suspend (C) -> R,
    ): R {
        if (!busy.compareAndSet(false, true)) throw NestedConnectionError()
        try {
            return suspendCancellableCoroutine { cont ->
                val inner = AtomicReference<Job?>(null)
                cont.invokeOnCancellation {
                    cancel.fire()
                    inner.get()?.cancel()
                }
                try {
                    device.requestConnection(type) { result ->
                        if (!cont.isActive) return@requestConnection
                        val outcome: Result<R> = try {
                            val connection = result.value
                            Result.success(
                                runBlocking {
                                    inner.set(coroutineContext[Job])
                                    if (cancel.isFired) throw CancellationException("geannuleerd")
                                    block(connection)
                                },
                            )
                        } catch (t: Throwable) {
                            Result.failure(KeyErrors.map(t, disconnected()))
                        }
                        outcome.fold(
                            onSuccess = { cont.resume(it) },
                            onFailure = { if (it is CancellationException) cont.cancel(it) else cont.resumeWithException(it) },
                        )
                    }
                } catch (t: Throwable) {
                    // requestConnection gooit IllegalStateException zonder USB-permissie of bij een
                    // niet-ondersteund verbindingstype.
                    val mapped = if (t is IllegalStateException && t !is NestedConnectionError) KeyError.Io("geen-toegang") else KeyErrors.map(t, disconnected())
                    cont.resumeWithException(mapped)
                }
            }
        } finally {
            busy.set(false)
        }
    }
}
