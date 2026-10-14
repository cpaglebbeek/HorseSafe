package nl.icthorse.horsesafe.pairing

import java.io.IOException
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import javax.crypto.Cipher
import kotlin.math.abs
import kotlinx.coroutines.delay
import nl.icthorse.horsesafe.crypto.B64u
import nl.icthorse.horsesafe.crypto.PairV1
import nl.icthorse.horsesafe.crypto.SealException
import nl.icthorse.horsesafe.crypto.SealV2
import nl.icthorse.horsesafe.crypto.X25519
import nl.icthorse.horsesafe.keystore.KeySlot
import nl.icthorse.horsesafe.keystore.KeysInvalidatedException
import nl.icthorse.horsesafe.keystore.KeystoreUnavailableException
import nl.icthorse.horsesafe.keystore.PhoneKeys
import nl.icthorse.horsesafe.net.ApiException
import nl.icthorse.horsesafe.net.ClaimRequest
import nl.icthorse.horsesafe.net.DevKeySigner
import nl.icthorse.horsesafe.net.DeviceApi
import nl.icthorse.horsesafe.net.DeviceKey
import nl.icthorse.horsesafe.net.DeviceState

/** Vinger vragen voor een Keystore-bewerking (in de app: `biometric/StrongGate`; in tests: nep). */
interface Finger {
    /** Ontgrendelt [cipher] (K_wrap) met één vinger; gooit bij annuleren of fout. */
    suspend fun cipher(cipher: Cipher, step: FingerStep): Cipher

    /** Ontgrendelt [signature] (K_biosig) met één vinger. */
    suspend fun signature(signature: Signature, step: FingerStep): Signature
}

/** Waarvoor de vinger nodig is; bepaalt de tekst in de systeemprompt. */
enum class FingerStep(val title: String, val subtitle: String) {
    WRAP("Telefoon koppelen (1 van 2)", "Leg je vinger op de sensor om de sleutel van deze telefoon te beschermen."),
    SIGN("Telefoon koppelen (2 van 2)", "Leg je vinger nog een keer op de sensor om de koppeling te ondertekenen."),
    TRIAL("Proef: kopie openen", "Leg je vinger op de sensor om de verzegelde kopie op deze telefoon te openen."),
}

/** Toestelgegevens voor het claim-request (geen geheim). */
data class DeviceInfo(val label: String, val model: String, val appVersion: String) {
    companion object {
        /**
         * Zelfde tekenregel als de server (§13.5 stap 1): stuurtekens (incl. \0), Unicode-opmaaktekens (Cf, bv.
         * U+202E of U+200B), losse surrogaten en U+2028/U+2029 eruit (per code point, zodat een emoji als
         * surrogaatpaar blijft staan), witruimte samengevoegd, maximaal [max] tekens; leeg → [fallback].
         */
        fun clean(raw: String?, max: Int, fallback: String): String {
            val kept = StringBuilder()
            (raw ?: "").codePoints().forEach { cp -> if (allowed(cp)) kept.appendCodePoint(cp) }
            val s = kept.toString().replace(Regex("\\s+"), " ").trim()
            val cut = if (s.codePointCount(0, s.length) > max) s.substring(0, s.offsetByCodePoints(0, max)).trim() else s
            return cut.ifEmpty { fallback }
        }

        /** Mag dit code point in label/model/app_version? (Cc, Cf, Cs, Zl en Zp niet.) */
        fun allowed(cp: Int): Boolean = when (Character.getType(cp).toByte()) {
            Character.CONTROL, Character.FORMAT, Character.SURROGATE,
            Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR,
            -> false
            else -> true
        }
    }
}

/** Fouten van het koppelen; de UI zet ze om in Nederlandse tekst. */
sealed class PairingError : Exception() {
    /** Vingerafdruk is veranderd of de sleutels zijn weg: alles is lokaal gewist (scherm "Opnieuw koppelen"). */
    data object KeysInvalidated : PairingError()
    data class Keystore(val why: String) : PairingError()
    data class Api(val status: Int, val code: String?, val reason: String?) : PairingError()
    data object SasMismatch : PairingError()
    data object ChainShape : PairingError()
    data object NotPaired : PairingError()

    /** Server meldt `revoked` (200): alles is lokaal gewist. */
    data object Revoked : PairingError()

    /**
     * 401/404 van de device-API: tijdelijk of onduidelijk (klok, net verwijderd, server even anders); er is NIETS
     * gewist (§13.3 stap 5). [clockSkewSeconds] = toestelklok min `Date` van de server als die bij een 401 meer
     * dan 60 s afwijkt (§13.6), anders null.
     */
    data class DeviceUnknown(val status: Int, val clockSkewSeconds: Long?) : PairingError()
    data object Timeout : PairingError()
    data object Storage : PairingError()
    data class Unseal(val code: String) : PairingError()
}

/** Resultaat van de proef "Kopie openen": alleen welke delen er waren, nooit de inhoud. */
data class TrialResult(val hasPh: Boolean, val hasKh: Boolean)

/**
 * Koppelflow van de telefoon (HARDWARE_KEYS §13.3 stap 2, 5 en 6). Geen Android-UI; draait in een coroutine
 * buiten de main thread (de vinger schakelt zelf naar de main thread).
 *
 * Geheimen: `s`, k_srv, k_web en sk_c staan alleen kort in een ByteArray en worden in `finally` gewist;
 * sk_c wordt alleen gewikkeld (K_wrap) opgeslagen.
 */
class PairingFlow(
    private val keys: PhoneKeys,
    private val finger: Finger,
    private val api: DeviceApi,
    private val store: DeviceStore,
    private val random: SecureRandom = SecureRandom(),
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
) {
    /** Device-handtekening (§13.6) met K_dev uit de sleutelset van [rec]. */
    private fun devSigner(rec: DeviceRecord) = DevKeySigner { msg -> keys.signDev(rec.slot, msg) }

    fun current(): DeviceRecord? = store.load()

    /**
     * Zijn de koppelsleutels nog bruikbaar? Een gewijzigde vingerafdruk maakt K_biosig en K_wrap
     * blijvend ongeldig (KeyPermanentlyInvalidatedException al bij init, zonder vinger). Ongeldig of weg →
     * alles lokaal wissen en false (scherm "Opnieuw koppelen").
     */
    fun keysValid(): Boolean {
        val slot = store.load()?.slot ?: KeySlot.A
        if (!keys.present(slot)) {
            wipeLocal()
            return false
        }
        return try {
            keys.biosigSignature(slot)
            keys.wrapCipher(slot)
            true
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            false
        } catch (e: KeystoreUnavailableException) {
            true
        } catch (e: GeneralSecurityException) {
            true
        }
    }

    /** Alles lokaal wissen: koppelbestand en de Keystore-sleutels (beide sets). */
    fun wipeLocal() {
        store.wipe()
        keys.deleteAll()
    }

    /**
     * Stap 2: sleutels maken, sk_c wikkelen (vinger 1), transcript ondertekenen (vinger 2), claimen.
     * [qr] wordt altijd gewist. Na succes staat de koppeling lokaal als `pending` met de SAS.
     *
     * De nieuwe sleutels komen in de sleutelset die NIET in gebruik is (tijdelijke aliassen). Pas na een
     * geslaagde claim (201, SAS klopt, opgeslagen) wordt die set de actieve en gaat de oude koppeling weg;
     * mislukt of annuleert iets, dan worden alleen de nieuwe sleutels gewist en blijft de oude koppeling staan.
     */
    suspend fun claim(qr: PairingQr, info: DeviceInfo): DeviceRecord {
        val kSrv = PairV1.kSrv(qr.secret)
        val kWeb = PairV1.kWeb(qr.secret)
        qr.wipe()
        val skC = X25519.newPrivate(random)
        val slot = (store.load()?.slot ?: KeySlot.B).other() // eerste koppeling → A
        var success = false
        try {
            val att = PairV1.attChallenge(qr.pairingId, kSrv)
            val material = try {
                keys.create(att, slot)
            } catch (e: KeystoreUnavailableException) {
                throw PairingError.Keystore(e.why)
            }
            val devChain = material.kDevChain.map(B64u::encode)
            val bioChain = material.kBiosigChain.map(B64u::encode)
            if (!chainOk(devChain) || !chainOk(bioChain)) throw PairingError.ChainShape

            val pkC = B64u.encode(X25519.publicKey(skC))

            // Vinger 1: sk_c wikkelen met K_wrap.
            val wrap = finger.cipher(guard { keys.wrapCipher(slot) }, FingerStep.WRAP)
            val wrappedCt = guard { wrap.doFinal(skC) }
            val wrappedIv = wrap.iv ?: throw PairingError.Keystore("geen iv")
            skC.fill(0)

            val fields = PairV1.Fields(
                pairingId = qr.pairingId,
                pkC = pkC,
                kDevPub = B64u.encode(material.kDevSpki),
                kBiosigPub = B64u.encode(material.kBiosigSpki),
                label = info.label,
                model = info.model,
                appVersion = info.appVersion,
            )
            val transcript = PairV1.transcript(fields)

            // Vinger 2: transcript ondertekenen met K_biosig.
            val sig = finger.signature(guard { keys.biosigSignature(slot) }, FingerStep.SIGN)
            val sigBiosig = guard {
                sig.update(transcript)
                sig.sign()
            }

            val localSas = PairV1.sas(transcript)
            val req = ClaimRequest(
                pkC = fields.pkC,
                kDevPub = fields.kDevPub,
                kBiosigPub = fields.kBiosigPub,
                kDevChain = devChain,
                kBiosigChain = bioChain,
                label = fields.label,
                model = fields.model,
                appVersion = fields.appVersion,
                macSrv = B64u.encode(PairV1.mac(kSrv, transcript)),
                macWeb = B64u.encode(PairV1.mac(kWeb, transcript)),
                sigBiosig = B64u.encode(sigBiosig),
            )
            val resp = try {
                api.claim(qr.pairingId, req)
            } catch (e: ApiException) {
                throw PairingError.Api(e.status, e.code, e.reason)
            }
            // De telefoon rekent de SAS zelf; wijkt die van de server af, dan klopt er iets niet.
            if (!MessageDigest.isEqual(resp.sas.toByteArray(), localSas.toByteArray())) throw PairingError.SasMismatch
            val rec = DeviceRecord(resp.deviceId, LocalState.PENDING, localSas, info.label, wrappedIv, wrappedCt, emptyList(), clockMillis() / 1000, slot)
            try {
                store.save(rec) // omwisselen: vanaf nu is [slot] de actieve set
            } catch (e: IOException) {
                throw PairingError.Storage
            }
            success = true
            keys.delete(slot.other()) // oude koppeling (of een verweesde set) weg
            return rec
        } catch (e: KeysInvalidatedException) {
            throw PairingError.KeysInvalidated
        } finally {
            kSrv.fill(0)
            kWeb.fill(0)
            skC.fill(0)
            // Mislukt of afgebroken (ook annuleren bij de vinger): alleen de nieuwe (tijdelijke) sleutels wissen;
            // een bestaande koppeling blijft onaangeroerd.
            if (!success) keys.delete(slot)
        }
    }

    /**
     * Stap 5: `GET /device/v1/status` elke [intervalMs] tot `active` (max [maxMs]). Alleen `revoked` (200) →
     * lokaal wissen. 401/404 → [PairingError.DeviceUnknown] zonder te wissen; netwerk/5xx/429 → verder pollen.
     */
    suspend fun awaitActive(intervalMs: Long = 2_000, maxMs: Long = 600_000): DeviceRecord {
        val start = clockMillis()
        while (true) {
            val rec = store.load() ?: throw PairingError.NotPaired
            if (rec.state == LocalState.ACTIVE) return rec
            val next = refresh(rec, transientOk = true)
            if (next?.state == LocalState.ACTIVE) return next
            if (clockMillis() - start >= maxMs) throw PairingError.Timeout
            delay(intervalMs)
        }
    }

    /**
     * Status één keer ophalen en lokaal bijwerken. null = tijdelijk niet bereikbaar (bij [transientOk]).
     * Wissen gebeurt ALLEEN bij een 200 met `state: "revoked"` (§13.4). 401 en 404 zijn geen bewijs van
     * intrekking (verkeerde klok, net opgeruimde claim, storing): melden, niets wissen.
     */
    suspend fun refresh(rec: DeviceRecord? = store.load(), transientOk: Boolean = false): DeviceRecord? {
        val r = rec ?: throw PairingError.NotPaired
        val st = try {
            guard { api.status(r.deviceId, devSigner(r)) }
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } catch (e: ApiException) {
            when {
                e.status == 401 || e.status == 404 -> throw PairingError.DeviceUnknown(e.status, clockSkewSeconds(e))
                transientOk && (e.status == 0 || e.status >= 500 || e.status == 429) -> return null
                else -> throw PairingError.Api(e.status, e.code, e.reason)
            }
        }
        return when (st.state) {
            DeviceState.REVOKED -> {
                wipeLocal()
                throw PairingError.Revoked
            }
            DeviceState.PENDING -> r
            DeviceState.ACTIVE -> r.with(state = LocalState.ACTIVE, keys = st.keys).also {
                try {
                    store.save(it)
                } catch (e: IOException) {
                    throw PairingError.Storage
                }
            }
        }
    }

    /**
     * Stap 6 (proef): verzegelde kopie ophalen, sk_c uitpakken met één vinger, Seal_v2 openen met de EIGEN
     * vault_id/key_id, alleen de vorm {ph,kh} controleren en alles wissen. Niets wordt getoond of bewaard.
     */
    suspend fun trialOpen(key: DeviceKey): TrialResult {
        val rec = store.load() ?: throw PairingError.NotPaired
        val own = rec.keys.firstOrNull { it.keyId == key.keyId && it.vaultId == key.vaultId } ?: throw PairingError.NotPaired
        val copy = try {
            guard { api.sealed(rec.deviceId, own.keyId, devSigner(rec)) }
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } catch (e: ApiException) {
            if (e.status == 401) throw PairingError.DeviceUnknown(401, clockSkewSeconds(e))
            throw PairingError.Api(e.status, e.code, e.reason)
        }
        if (copy.keyId != own.keyId || copy.vaultId != own.vaultId) throw PairingError.Unseal("unseal_failed")
        var sk: ByteArray? = null
        try {
            val c = finger.cipher(guard { keys.unwrapCipher(rec.slot, rec.wrappedIv) }, FingerStep.TRIAL)
            sk = guard { c.doFinal(rec.wrappedCt) }
            if (sk.size != X25519.KEY_LEN) throw PairingError.Unseal("unseal_failed")
            val secret = try {
                SealV2.open(copy.sealed, sk, SealV2.PURPOSE_STORE, own.vaultId, own.keyId)
            } catch (e: SealException) {
                throw PairingError.Unseal(e.code)
            }
            val result = TrialResult(secret.ph != null, secret.kh != null)
            secret.wipe()
            return result
        } catch (e: KeysInvalidatedException) {
            wipeLocal()
            throw PairingError.KeysInvalidated
        } finally {
            sk?.fill(0)
        }
    }

    /** Keystore-uitzonderingen omzetten; [KeysInvalidatedException] gaat door naar de aanroeper. */
    private inline fun <T> guard(block: () -> T): T = try {
        block()
    } catch (e: KeystoreUnavailableException) {
        throw PairingError.Keystore(e.why)
    } catch (e: GeneralSecurityException) {
        throw PairingError.Keystore("bewerking geweigerd")
    }

    private fun chainOk(chain: List<String>): Boolean = chain.size in 2..6 && chain.all { it.length <= 4096 }

    /**
     * Bij een 401: wijkt de `Date`-header van de server meer dan [CLOCK_SKEW_MAX_S] af van de toestelklok, dan is
     * de klok de waarschijnlijke oorzaak (de server eist `|nu − ts| ≤ 60`, §13.6). Positief = telefoon loopt voor.
     */
    private fun clockSkewSeconds(e: ApiException): Long? {
        if (e.status != 401) return null
        val server = e.serverDateMillis ?: return null
        val skew = (clockMillis() - server) / 1000
        return skew.takeIf { abs(it) > CLOCK_SKEW_MAX_S }
    }

    companion object {
        const val CLOCK_SKEW_MAX_S = 60L
    }
}
