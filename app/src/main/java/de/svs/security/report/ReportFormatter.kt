package de.svs.security.report

import de.svs.security.history.LogEvent
import de.svs.security.scan.AppInfo
import de.svs.security.scan.RiskRules
import de.svs.security.scan.ScanResult
import de.svs.security.scan.Severity
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Alle Daten fuer die Gesamtuebersicht (reine Daten -> per Unit-Test pruefbar). */
data class ReportData(
    val created: Long,
    val device: String,
    val android: String,
    val securityPatch: String,
    val appVersion: String,
    val scan: ScanResult?,
    val deviceStatus: List<Pair<String, String>>,
    val apps: List<AppInfo>,
    val events: List<LogEvent>,
    val eventDays: Int,
    val intel: List<Pair<String, String>>,
    /** Apps ohne Symbol, die als unkritisch eingestuft wurden (Zeile mit Begruendung) */
    val cleared: List<String> = emptyList(),
)

/** Erzeugt die Gesamtuebersicht als gut lesbaren Text (zum Kopieren, Teilen oder Speichern). */
object ReportFormatter {
    private val dt = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.GERMANY)
    private fun t(x: Long) = if (x <= 0) "–" else dt.format(Date(x))

    private const val LINE = "════════════════════════════════════════"

    fun format(r: ReportData): String = buildString {
        appendLine("HANDYWÄCHTER – GESAMTÜBERSICHT")
        appendLine(LINE)
        appendLine("Erstellt:          ${t(r.created)}")
        appendLine("Gerät:             ${r.device}")
        appendLine("Android:           ${r.android} · Sicherheitspatch ${r.securityPatch}")
        appendLine("Handywächter:      ${r.appVersion}")
        appendLine()

        // 1. Gesamtbewertung
        section("1. GESAMTBEWERTUNG")
        val s = r.scan
        if (s == null) {
            appendLine("Noch keine Prüfung durchgeführt.")
        } else {
            val worst = s.worst
            val verdict = when {
                worst == null || worst == Severity.LOW -> "UNAUFFÄLLIG – keine verdächtige App gefunden"
                worst == Severity.MEDIUM -> "PRÜFEN – einige Punkte sollten angesehen werden"
                else -> "HANDLUNGSBEDARF – mindestens ein hoher/kritischer Befund"
            }
            appendLine("Ergebnis:          $verdict")
            appendLine("Sicherheitswert:   ${s.score}/100")
            appendLine("Letzte Prüfung:    ${t(s.time)}")
            appendLine("Geprüft:           ${s.appsScanned} Apps, davon ${s.apksHashed} per Fingerabdruck (SHA-256)")
            appendLine("Befunde:           " + Severity.entries.joinToString(" · ") { sev -> "${sev.label} ${s.findings.count { it.severity == sev }}" })
        }
        appendLine()

        // 2. Alle Befunde
        section("2. ALLE BEFUNDE (nach Schwere sortiert)")
        if (s == null || s.findings.isEmpty()) appendLine("Keine Befunde.")
        else s.findings.forEachIndexed { i, f ->
            appendLine("${i + 1}. [${f.levelText.uppercase()}] ${f.title}")
            if (f.facts.isNotEmpty()) {
                f.facts.forEach { (k, v) -> appendLine("   ${(k + ":").padEnd(21)} $v") }
                if (f.factors.isNotEmpty()) appendLine("   Score erhöht durch:")
                f.factors.forEach { appendLine("     $it") }
                if (f.neutral.isNotEmpty()) appendLine("   Als unkritisch eingestuft:")
                f.neutral.forEach { appendLine("     ✓ $it") }
            } else {
                if (f.pkg != null) appendLine("   Paket:      ${f.pkg}")
                appendLine("   Befund:     ${f.detail}")
            }
            appendLine("   Empfehlung: ${f.advice}")
            appendLine()
        }
        appendLine()

        if (r.cleared.isNotEmpty()) {
            section("2b. APPS OHNE SYMBOL – ALS UNKRITISCH EINGESTUFT (${r.cleared.size})")
            r.cleared.forEach { appendLine("• $it") }
            appendLine()
        }

        // 3. Geraetestatus
        section("3. GERÄTESTATUS")
        r.deviceStatus.forEach { (k, v) -> appendLine("${(k + ":").padEnd(32)} $v") }
        appendLine()

        // 4. Apps mit besonderen Rechten
        section("4. APPS MIT BESONDEREN RECHTEN")
        val roles = listOf<Pair<String, (AppInfo) -> Boolean>>(
            "Bedienungshilfe (kann Bildschirm lesen/bedienen)" to { it.accessibility },
            "Geräteadministrator" to { it.deviceAdmin },
            "Liest Benachrichtigungen" to { it.notificationListener },
            "Startbildschirm (Launcher)" to { it.defaultHome },
            "Standard-SMS-App" to { it.defaultSms },
            "Darf über anderen Apps einblenden (nur Nicht-System)" to { it.overlayAllowed },
        )
        roles.forEach { (title, pred) ->
            val list = r.apps.filter(pred)
            appendLine("$title: ${if (list.isEmpty()) "keine" else ""}")
            list.forEach { appendLine("   • ${appLine(it)}") }
        }
        appendLine()

        // 5. Apps aus unbekannter Quelle
        val side = r.apps.filter { RiskRules.isSideloaded(it) }.sortedByDescending { it.firstInstall }
        section("5. APPS AUS UNBEKANNTER QUELLE (nicht Play/Galaxy Store) – ${side.size}")
        if (side.isEmpty()) appendLine("Keine.")
        side.forEach { a ->
            appendLine("• ${a.label} (${a.pkg})")
            appendLine("   Quelle: ${RiskRules.installerLabel(a.installer)} · installiert ${t(a.firstInstall)} · Version ${a.versionName ?: "?"}")
            appendLine("   App-Symbol: ${if (a.hasLauncher) "ja" else "NEIN (versteckt)"} · Rechte: ${a.grantedPerms.size} erteilt")
            a.sha256?.let { appendLine("   SHA-256: $it") }
        }
        appendLine()

        // 6. Zuletzt installiert / aktualisiert
        val since = r.created - 14 * 86_400_000L
        val recent = r.apps.filter { !it.system && (it.firstInstall >= since || it.lastUpdate >= since) }.sortedByDescending { maxOf(it.firstInstall, it.lastUpdate) }
        section("6. IN DEN LETZTEN 14 TAGEN INSTALLIERT/AKTUALISIERT (Nutzer-Apps) – ${recent.size}")
        if (recent.isEmpty()) appendLine("Keine.")
        recent.forEach { a ->
            val what = if (a.firstInstall >= since) "neu installiert ${t(a.firstInstall)}" else "aktualisiert ${t(a.lastUpdate)}"
            appendLine("• ${a.label} (${a.pkg}) – $what – ${RiskRules.installerLabel(a.installer)}")
        }
        appendLine()

        // 7. Auffaellige Ereignisse
        val alerts = r.events.filter { it.alert }.sortedByDescending { it.time }
        section("7. AUFFÄLLIGE EREIGNISSE DER LETZTEN ${r.eventDays} TAGE – ${alerts.size}")
        if (alerts.isEmpty()) appendLine("Keine.")
        alerts.forEach { e ->
            appendLine("• ${t(e.time)}  ${e.title}")
            if (e.detail.isNotEmpty()) appendLine("     ${e.detail}")
            e.pkg?.let { appendLine("     Paket: $it") }
        }
        val counts = r.events.groupingBy { it.type }.eachCount()
        appendLine()
        appendLine("Ereignisse gesamt: ${r.events.size} (Entsperrt ${counts["UNLOCK"] ?: 0}× · Neustarts ${(counts["BOOT"] ?: 0) + (counts["SAFE_MODE"] ?: 0)} · " +
            "abgesicherter Modus ${counts["SAFE_MODE"] ?: 0}× · Installationen ${counts["INSTALL"] ?: 0} · Daten gelöscht ${counts["DATA_CLEARED"] ?: 0} · blockierte Seiten ${counts["BLOCKED"] ?: 0})")
        appendLine()

        // 8. Bedrohungsdaten
        section("8. STAND DER BEDROHUNGSDATEN")
        r.intel.forEach { (k, v) -> appendLine("${(k + ":").padEnd(32)} $v") }
        appendLine()

        // 9. Legende
        section("9. SO LIEST DU DIE BEWERTUNG")
        appendLine("Jede App erhält einen Risk Score 0–100 aus Herkunft, Identität (Signatur), Sonderrechten und deren Kombination.")
        appendLine("  0–19  Unauffällig      kein Treffer")
        appendLine(" 20–39  Geringes Risiko  meist harmlos, z. B. selbst installierte APK")
        appendLine(" 40–59  Prüfen           Sonderrechte prüfen – gewollt?")
        appendLine(" 60–79  Verdächtig       auffällige Kombination – App und Rechte prüfen")
        appendLine(" 80–100 Hohes Risiko     starke Kombination oder Übereinstimmung mit bekannter Spionage-App")
        appendLine("Ein fehlendes App-Symbol zählt nur 3 Punkte und ist bei Sprachpaketen, Plugins und Diensten normal.")
        appendLine("Die Bewertung ist ein Risiko-Hinweis, kein Nachweis von Schadsoftware (außer bei Indikator-Übereinstimmung).")
        appendLine("Hinweis: Android protokolliert, welche App wann aktiv war – nicht, welche Person das Handy bedient hat.")
        appendLine(LINE)
    }

    private fun StringBuilder.section(title: String) {
        appendLine(title)
        appendLine("─".repeat(minOf(title.length, 40)))
    }

    private fun appLine(a: AppInfo) =
        "${a.label} (${a.pkg}) – ${if (a.system) "Systemapp" else RiskRules.installerLabel(a.installer)}"

    fun fileName(created: Long) = "Handywaechter-Bericht_" + SimpleDateFormat("yyyy-MM-dd_HHmm", Locale.GERMANY).format(Date(created)) + ".txt"
}
