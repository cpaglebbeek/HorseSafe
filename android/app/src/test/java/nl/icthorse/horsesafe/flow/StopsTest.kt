package nl.icthorse.horsesafe.flow

import kotlinx.coroutines.runBlocking
import nl.icthorse.horsesafe.flow.fake.FakeYubiKey
import nl.icthorse.horsesafe.flow.fake.KeySpec
import nl.icthorse.horsesafe.flow.fake.KeyProfiles
import nl.icthorse.horsesafe.flow.fake.SetupDriver
import nl.icthorse.horsesafe.yubikey.api.Firmware
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Elke harde stop op het juiste moment, en na een stop geen schrijfactie meer. */
class StopsTest {

    private suspend fun stopOf(spec: KeySpec, profile: Profile, policy: MaxPinLengthPolicy = MaxPinLengthPolicy.ASSUME_CTAP21_MAX,
                               prep: (FakeYubiKey) -> Unit = {}): Pair<State.Stopped, FakeYubiKey> {
        val key = FakeYubiKey(spec).also(prep)
        val d = SetupDriver(key, profile, policy = policy)
        val end = d.runNew()
        assertTrue("verwacht een stop, kreeg $end", end is State.Stopped)
        // Na de stop: nog meer events leiden nergens toe.
        val writes = key.writes()
        d.send(FlowEvent.IrreversibleConfirmed); d.send(FlowEvent.EnrollFinger("X-test")); d.send(FlowEvent.Retry); d.send(FlowEvent.FingersDone)
        assertEquals("geen schrijfactie na een stop", writes, key.writes())
        assertTrue(d.machine.history.last() is State.Stopped)
        return end as State.Stopped to key
    }

    private fun assertNoWrites(key: FakeYubiKey) = assertEquals(emptyList<String>(), key.writes())

    // ---------------------------------------------------------------- F1 detectie

    @Test fun bio571IsTeOud() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.bio571(), Profile.BIO_MAIN)
        assertEquals(Stop.FIRMWARE_TOO_OLD_BIO, s.stop); assertNoWrites(key); assertEquals(emptySet<Written>(), s.written)
    }

    @Test fun yk5Onder570IsTeOud() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.yk5_569(), Profile.RECOVERY_YK5)
        assertEquals(Stop.FIRMWARE_TOO_OLD_YK5, s.stop); assertNoWrites(key)
    }

    @Test fun yk5_570MagWel() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.yk5_57().copy(firmware = Firmware(5, 7, 0))), Profile.RECOVERY_YK5)
        assertTrue(d.runNew() is State.ReportReady)
    }

    @Test fun yk5_542ZonderFido21() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.yk5_542(), Profile.RECOVERY_YK5)
        assertEquals(Stop.NO_FIDO_2_1, s.stop); assertNoWrites(key)
    }

    @Test fun ontbrekendeOpties() = runBlocking {
        val base = KeyProfiles.yk5_57()
        assertEquals(Stop.MISSING_SET_MIN_PIN_LENGTH, stopOf(base.copy(setMinPinLengthOption = false), Profile.RECOVERY_YK5).first.stop)
        assertEquals(Stop.MISSING_AUTHNR_CFG, stopOf(base.copy(authnrCfg = false), Profile.RECOVERY_YK5).first.stop)
        assertEquals(Stop.MISSING_ALWAYS_UV, stopOf(base.copy(alwaysUv = null), Profile.RECOVERY_YK5).first.stop)
        assertEquals(Stop.MAX_RPIDS_TOO_LOW, stopOf(base.copy(maxRpids = 0), Profile.RECOVERY_YK5).first.stop)
    }

    @Test fun firmwareOnbekend() = runBlocking {
        assertEquals(Stop.FIRMWARE_UNKNOWN, stopOf(KeyProfiles.bioFido574().copy(managementAvailable = false), Profile.BIO_MAIN).first.stop)
    }

    @Test fun aaguidNietOpDeLijst() = runBlocking {
        assertEquals(Stop.AAGUID_NOT_ALLOWED, stopOf(KeyProfiles.bioFido574().copy(aaguid = KeyProfiles.NOT_LISTED), Profile.BIO_MAIN).first.stop)
    }

    @Test fun klassePastNietBijProfiel() = runBlocking {
        assertEquals(Stop.CLASS_MISMATCH, stopOf(KeyProfiles.yk5_57(), Profile.BIO_MAIN).first.stop)
        assertEquals(Stop.CLASS_MISMATCH, stopOf(KeyProfiles.bioFido574(), Profile.RECOVERY_YK5).first.stop)
    }

    @Test fun mpeMax8() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.bioMpeMax8(), Profile.BIO_MAIN)
        assertEquals(Stop.MAX_PIN_LENGTH_TOO_SHORT, s.stop); assertNoWrites(key)
    }

    @Test fun maxPinLengthAfwezigAlleenStopBijStrengBeleid() = runBlocking {
        assertEquals(Stop.MAX_PIN_LENGTH_UNKNOWN, stopOf(KeyProfiles.bioNo1D(), Profile.BIO_MAIN, MaxPinLengthPolicy.STOP).first.stop)
        // 0.3.2: MPE zonder 0x1D gaat door tot setPin; met PIV aan (max 8) weigert die, er staat niets op de sleutel.
        val (s, key) = stopOf(KeyProfiles.bioMpeHidden(), Profile.BIO_MAIN)
        assertEquals(Stop.PIN_POLICY_MPE_PIV, s.stop)
        assertEquals(emptySet<Written>(), s.written)
        assertNull(key.pin)
    }

    @Test fun klasseFoutNoemtTypeEnRol() = runBlocking {
        val (s, _) = stopOf(KeyProfiles.bioFido574(), Profile.RECOVERY_YK5)
        assertEquals(Stop.CLASS_MISMATCH, s.stop)
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.RECOVERY_YK5)
        d.detect()
        val det = d.machine.history.filterIsInstance<State.Detected>().last()
        val line = det.checks.first { it.id == "klasse" }
        assertTrue(line.detail, line.detail.contains("Aangesloten: ") && line.detail.contains("Gekozen rol: Noodsleutel (YubiKey 5)") && line.detail.contains("bio"))
    }

    @Test fun setPinIsDeVeiligeProef() = runBlocking {
        // FIDO-AAGUID maar stil max 8: setPin(63) faalt, er staat niets op de sleutel.
        val (s, key) = stopOf(KeyProfiles.bioFidoHiddenMax8(), Profile.BIO_MAIN)
        assertEquals(Stop.PIN_POLICY_MPE_PIV, s.stop)
        assertEquals(emptySet<Written>(), s.written)
        assertNull(key.pin)
        assertFalse("setMinPinLength" in key.log)
    }

    @Test fun complexiteitsbeleidGeeftEigenStop() = runBlocking {
        val (s, _) = stopOf(KeyProfiles.bioFidoHiddenMax8().copy(pinComplexity = true), Profile.BIO_MAIN)
        assertEquals(Stop.PIN_POLICY_COMPLEXITY, s.stop)
    }

    @Test fun meerdereSleutelsEnLoskoppelen() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d.detect()
        assertEquals(Stop.MULTIPLE_KEYS, (d.send(FlowEvent.MultipleKeys) as State.Stopped).stop)

        val d2 = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d2.detect(); d2.pinUntilRetyped()
        val s = d2.send(FlowEvent.KeyRemoved) as State.Stopped
        assertEquals(Stop.KEY_REMOVED, s.stop)
        assertEquals(setOf(Written.PIN), s.written)

        val d3 = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d3.detect()
        assertEquals(Stop.MULTIPLE_KEYS, (d3.send(FlowEvent.KeyConnected(FakeYubiKey(KeyProfiles.bioFido574()))) as State.Stopped).stop)
    }

    // ---------------------------------------------------------------- nieuw-sleutelgate

    @Test fun gebruikteSleutelMetPin() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.bioFido574(), Profile.BIO_MAIN) { it.preset(pin = "abcd".toCharArray(), fingers = listOf("X"), resident = 1) }
        assertEquals(Stop.PIN_ALREADY_SET, s.stop); assertNoWrites(key)
    }

    @Test fun bioMetVingersZonderPin() = runBlocking {
        assertEquals(Stop.BIO_ALREADY_ENROLLED, stopOf(KeyProfiles.bioFido574(), Profile.BIO_MAIN) { it.preset(fingers = listOf("X")) }.first.stop)
        assertEquals(Stop.RECOVERY_BIO_HAS_FINGER, stopOf(KeyProfiles.bioFido574(), Profile.RECOVERY_BIO) { it.preset(fingers = listOf("X")) }.first.stop)
    }

    @Test fun forcePinChangeEnMinderDan8Pogingen() = runBlocking {
        assertEquals(Stop.FORCE_PIN_CHANGE, stopOf(KeyProfiles.yk5_57(), Profile.RECOVERY_YK5) { it.preset(forceChange = true) }.first.stop)
        assertEquals(Stop.KEY_ALREADY_USED, stopOf(KeyProfiles.yk5_57(), Profile.RECOVERY_YK5) { it.preset(retries = 7) }.first.stop)
    }

    @Test fun residentCredentialZonderPinGeeftStopNaSetPin() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.bioFido574(), Profile.BIO_MAIN) { it.residentCredentials = 1 }
        assertEquals(Stop.KEY_ALREADY_USED, s.stop)
        assertEquals(setOf(Written.PIN), s.written)
        assertFalse("setMinPinLength" in key.log)
    }

    // ---------------------------------------------------------------- omgeving en herstart

    @Test fun omgevingBlokkeertDePin() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        val det = d.detect(listOf(Stop.ENV_ADB))
        assertTrue("M0-M2 werken nog: $det", det is State.GateNewOk)
        val env = d.machine.history[1] as State.EnvOk
        assertEquals(Verdict.RED, env.warnings.single().verdict)
        val s = d.send(FlowEvent.ChecklistConfirmed) as State.Stopped
        assertEquals(Stop.ENV_ADB, s.stop)
        assertNull(d.machine.revealPin { it })

        val d2 = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d2.detect(); d2.send(FlowEvent.ChecklistConfirmed)
        assertTrue(d2.state is State.PinGenerated)
        val s2 = d2.send(FlowEvent.EnvironmentChecked(listOf(Stop.ENV_SCREEN_RECORDING))) as State.Stopped
        assertEquals(Stop.ENV_SCREEN_RECORDING, s2.stop)
        assertNull("PIN gewist", d2.machine.revealPin { it })
    }

    @Test fun herstartVoorEnNaSetPin() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d.detect(); d.send(FlowEvent.ChecklistConfirmed); d.send(FlowEvent.RevealFinished)
        assertEquals(Stop.RESTART_BEFORE_PIN, (d.send(FlowEvent.Recreated) as State.Stopped).stop)
        assertNull(d.key.pin)

        val d2 = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d2.detect(); d2.pinUntilRetyped()
        val s = d2.send(FlowEvent.Recreated) as State.Stopped
        assertEquals(Stop.PROCESS_RESTARTED, s.stop)
        assertEquals(setOf(Written.PIN), s.written)
    }

    @Test fun annuleren() = runBlocking {
        val d = SetupDriver(FakeYubiKey(KeyProfiles.bioFido574()), Profile.BIO_MAIN)
        d.detect(); d.pinUntilRetyped(); d.confirmIrreversible()
        val s = d.send(FlowEvent.Cancel) as State.Stopped
        assertEquals(Stop.CANCELLED, s.stop)
        assertEquals(setOf(Written.PIN, Written.MIN_PIN_LENGTH_63, Written.ALWAYS_UV), s.written)
    }

    // ---------------------------------------------------------------- attestation

    @Test fun attestationFoutenVoorDePinBijYk5() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.yk5_57().copy(attFmt = "none"), Profile.RECOVERY_YK5)
        assertEquals(Stop.ATTEST_NOT_PACKED, s.stop)
        assertFalse("setPin" in key.log)
        val (s2, key2) = stopOf(KeyProfiles.yk5_57().copy(genuine = false), Profile.RECOVERY_YK5)
        assertEquals(Stop.ATTEST_CHAIN_INVALID, s2.stop)
        assertNoWrites(key2)
    }

    @Test fun attestationFoutBijBioNaSetPinVoorMinimum() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.bioFido574().copy(genuine = false), Profile.BIO_MAIN)
        assertEquals(Stop.ATTEST_CHAIN_INVALID, s.stop)
        assertEquals(setOf(Written.PIN), s.written)
        assertFalse("setMinPinLength" in key.log)
    }

    // ---------------------------------------------------------------- teruglezen

    @Test fun terugleesfoutenConfig() = runBlocking {
        val (s, key) = stopOf(KeyProfiles.bioFido574(), Profile.BIO_MAIN) { it.lieAboutMinPinLength = true }
        assertEquals(Stop.MIN_PIN_LENGTH_READBACK_FAILED, s.stop)
        assertEquals(setOf(Written.PIN, Written.MIN_PIN_LENGTH_63), s.written)
        assertFalse("toggleAlwaysUv" in key.log)
        assertFalse(key.log.any { it.startsWith("enroll") })

        val (s2, _) = stopOf(KeyProfiles.yk5_57(), Profile.RECOVERY_YK5) { it.ignoreToggle = true }
        assertEquals(Stop.ALWAYS_UV_READBACK_FAILED, s2.stop)

        val (s3, _) = stopOf(KeyProfiles.bioFido574().copy(refusesMin63 = true), Profile.BIO_MAIN)
        assertEquals(Stop.MIN_PIN_LENGTH_READBACK_FAILED, s3.stop)
        assertEquals(setOf(Written.PIN), s3.written)
    }

    @Test fun elkeStopHeeftTekstEnAdvies() {
        Stop.entries.forEach { assertTrue(it.name, it.tekst.isNotBlank() && it.advies.isNotBlank()) }
    }
}
