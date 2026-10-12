package nl.icthorse.horsesafe.report

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import java.io.IOException

/**
 * Export en import van rapporten via de opslagkiezer van Android (SAF). De UI start
 * [createDocumentIntent] / [openDocumentIntent] (of `ActivityResultContracts.CreateDocument/OpenDocument`
 * met [ReportStore.MIME_TYPE]) en geeft de gekozen URI hier door. Geen netwerk; alleen de URI die de
 * gebruiker zelf koos.
 */
class SafReportIo(
    private val resolver: ContentResolver,
    private val store: ReportStore,
) {
    /** Schrijft [report] naar [uri] (overschrijft, modus "wt"). */
    fun export(uri: Uri, report: Report) {
        val out = resolver.openOutputStream(uri, "wt") ?: throw IOException("bestand kon niet worden geopend")
        out.use { store.exportTo(it, report) }
    }

    /** Leest één rapport uit [uri] met schemacontrole en bewaart het in de app-privéopslag. */
    fun import(uri: Uri): ReportStore.ImportResult {
        val input = resolver.openInputStream(uri) ?: throw IOException("bestand kon niet worden geopend")
        return input.use { store.importFrom(it) }
    }

    companion object {
        fun createDocumentIntent(report: Report): Intent =
            Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = ReportStore.MIME_TYPE
                putExtra(Intent.EXTRA_TITLE, ReportStore.suggestedFileName(report))
            }

        fun openDocumentIntent(): Intent =
            Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = ReportStore.MIME_TYPE
            }
    }
}
