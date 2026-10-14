package nl.icthorse.horsesafe.keystore

import java.security.ProviderException

/**
 * StrongBox eerst, anders de TEE (§13.2). Alleen een fout tijdens de generatie MÉT StrongBox leidt tot de
 * terugval: [android.security.keystore.StrongBoxUnavailableException] (een subklasse van
 * [ProviderException]) én een kale [ProviderException], die sommige toestellen gooien als de StrongBox-chip de
 * sleutel weigert (bv. attestation of `unlockedDeviceRequired` niet ondersteund) of tijdelijk niet antwoordt.
 * De poging zonder StrongBox wordt gewoon uitgevoerd; een fout daarvan gaat ongewijzigd naar de aanroeper.
 *
 * Los van [AndroidPhoneKeys] (geen Android-API) zodat de regel op de JVM te testen is.
 */
internal object StrongBoxFallback {
    inline fun <T> generate(gen: (strongBox: Boolean) -> T): T = try {
        gen(true)
    } catch (e: ProviderException) {
        gen(false)
    }
}
