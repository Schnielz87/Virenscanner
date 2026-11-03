package de.svs.security

import de.svs.security.history.LogEvent
import de.svs.security.report.ReportData
import de.svs.security.report.ReportFormatter
import de.svs.security.scan.AppInfo
import de.svs.security.scan.Finding
import de.svs.security.scan.FixAction
import de.svs.security.scan.ScanResult
import de.svs.security.scan.Severity
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportFormatterTest {
    private val now = 1_800_000_000_000L
    private fun app(pkg: String, installer: String?, acc: Boolean = false, launcher: Boolean = true, first: Long = now - 86_400_000L) =
        AppInfo(pkg, pkg.substringAfterLast('.'), false, installer, first, first, "1.0", null, emptyList(), emptySet(), launcher, acc, false, false, false, false, false)

    @Test fun containsAllSections() {
        val scan = ScanResult(now, 120, 30, listOf(
            Finding(Severity.HIGH, "Versteckte App ohne Symbol: evil", "Details", "Deinstallieren", "com.evil", FixAction.UNINSTALL),
            Finding(Severity.LOW, "Aus unbekannter Quelle installiert: tool", "d", "a", "com.tool"),
        ))
        val txt = ReportFormatter.format(ReportData(
            now, "samsung SM-S921B", "Android 15", "2026-10-01", "1.0.2", scan,
            listOf("Abgesicherter Modus aktiv" to "nein"),
            listOf(app("com.evil", "com.sec.android.app.sbrowser", acc = true, launcher = false), app("com.good", "com.android.vending")),
            listOf(LogEvent(now - 3600_000, "SAFE_MODE", "Neustart im abgesicherten Modus", "Widgets entfernt", alert = true)),
            7, listOf("Gefährliche Webseiten" to "40000"),
        ))
        listOf("1. GESAMTBEWERTUNG", "HANDLUNGSBEDARF", "2. ALLE BEFUNDE", "[HOCH] Versteckte App", "Paket:      com.evil",
            "3. GERÄTESTATUS", "4. APPS MIT BESONDEREN RECHTEN", "Bedienungshilfe", "5. APPS AUS UNBEKANNTER QUELLE",
            "über Samsung Internet heruntergeladen", "NEIN (versteckt)", "6. IN DEN LETZTEN 14 TAGEN", "com.good",
            "7. AUFFÄLLIGE EREIGNISSE", "Neustart im abgesicherten Modus", "8. STAND DER BEDROHUNGSDATEN", "9. SO LIEST DU",
        ).forEach { assertTrue("fehlt: $it", it in txt) }
        // Play-Store-App gehoert nicht in "unbekannte Quelle"
        val sec5 = txt.substringAfter("5. APPS AUS UNBEKANNTER QUELLE").substringBefore("6. IN DEN")
        assertTrue("com.good" !in sec5)
    }

    @Test fun emptyScan() {
        val txt = ReportFormatter.format(ReportData(now, "x", "y", "z", "1", null, emptyList(), emptyList(), emptyList(), 7, emptyList()))
        assertTrue("Noch keine Prüfung" in txt)
    }
}
