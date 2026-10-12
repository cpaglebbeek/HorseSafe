package nl.icthorse.horsesafe.flow

/** Oordeel per eis (M2, M9, rapport). */
enum class Verdict { GREEN, ORANGE, RED }

/**
 * Eén regel in de beoordeling. [id] is een vaste sleutel (bv. `fido_2_1`, `firmware`, `max_pin_length`,
 * `u2f_after_always_uv`); [detail] is korte Nederlandse tekst zonder geheimen.
 */
data class CheckResult(val id: String, val verdict: Verdict, val detail: String)
