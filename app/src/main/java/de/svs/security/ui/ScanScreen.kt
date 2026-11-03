package de.svs.security.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.GppMaybe
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import de.svs.security.Actions
import de.svs.security.Tab
import de.svs.security.intel.ThreatIntel
import de.svs.security.scan.FixAction
import de.svs.security.scan.Finding
import de.svs.security.scan.Severity

@Composable
fun ScanScreen(vm: AppViewModel, modifier: Modifier, goTo: (Tab) -> Unit) {
    val result by vm.scan.collectAsState()
    val progress by vm.scanProgress.collectAsState()
    val intel by ThreatIntel.status.collectAsState()
    var showLow by rememberSaveable { mutableStateOf(false) }

    LazyColumn(modifier.fillMaxWidth(), contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            val worst = result?.worst
            val (icon, color, headline) = when {
                result == null -> Triple(Icons.Filled.GppMaybe, Svs.Grey, "Noch nicht geprüft")
                worst == null || worst == Severity.LOW -> Triple(Icons.Filled.CheckCircle, Svs.Green, "Keine verdächtigen Apps gefunden")
                worst == Severity.MEDIUM -> Triple(Icons.Filled.Warning, Svs.Amber, "Einige Punkte prüfen")
                else -> Triple(Icons.Filled.Warning, Svs.Red, "Handlungsbedarf")
            }
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(icon, null, tint = color, modifier = Modifier.size(56.dp))
                    Spacer(Modifier.width(14.dp))
                    Column {
                        Text(headline, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = color)
                        result?.let {
                            Muted("Sicherheitswert ${it.score}/100 · ${it.appsScanned} Apps, davon ${it.apksHashed} per Fingerabdruck geprüft")
                            Muted("Letzte Prüfung: ${fmtDateTime(it.time)}")
                        }
                        Muted("Bedrohungsdaten: ${intel.packages} Spionage-Apps, ${intel.hashes} Fingerabdrücke, ${intel.domains} gefährliche Webseiten · Stand ${fmtDateTime(intel.lastUpdate)}")
                    }
                }
                val p = progress
                if (p != null) {
                    LinearProgressIndicator(progress = { p.second }, modifier = Modifier.fillMaxWidth())
                    Muted(p.first)
                } else {
                    Button(onClick = { vm.startScan() }, modifier = Modifier.fillMaxWidth()) { Text("Jetzt vollständig prüfen") }
                }
            }
        }

        item {
            val busy by vm.reportBusy.collectAsState()
            SectionCard("Gesamtübersicht") {
                Body("Alle Treffer, Geräte-Status, Apps mit besonderen Rechten, Apps aus unbekannter Quelle, neue Installationen und auffällige Ereignisse der letzten 7 Tage auf einen Blick – zum Kopieren, Teilen oder als Datei.")
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                Button(onClick = { vm.buildReport() }, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Wird erstellt …" else "Gesamtübersicht erstellen") }
                if (result == null) Muted("Tipp: vorher „Jetzt vollständig prüfen“, damit alle Befunde enthalten sind.")
            }
        }

        item {
            SectionCard("Sperr-Meldung „Innenministerium / Cyberkriminalität“?", Svs.Amber) {
                Body("Das war eine Betrugsseite im Browser („Polizei-Trojaner“-Masche), kein echter Zugriff auf dein Handy. Nicht bezahlen. Was zu tun ist und warum die Widgets weg sein können, steht unter „Hilfe“.")
                OutlinedButton(onClick = { goTo(Tab.HELP) }) { Text("Zur Erklärung") }
                OutlinedButton(onClick = { goTo(Tab.HISTORY) }) { Text("Verlauf von gestern ansehen") }
            }
        }

        result?.let { r ->
            val important = r.findings.filter { it.severity <= Severity.MEDIUM }
            val low = r.findings.filter { it.severity > Severity.MEDIUM }
            if (important.isEmpty()) item {
                SectionCard("Keine kritischen Befunde", Svs.Green) {
                    Body("Keine Übereinstimmung mit bekannten Spionage-Apps und keine App mit verdächtiger Kombination aus Herkunft und Sonderrechten. Systemkomponenten ohne App-Symbol (z. B. Sprachpakete, Buds-Plugins) werden nicht als Risiko gewertet.")
                }
            }
            items(important) { FindingCard(it) }
            if (low.isNotEmpty()) item {
                FilterChip(selected = showLow, onClick = { showLow = !showLow }, label = { Text("${low.size} Hinweise mit geringem Risiko ${if (showLow) "ausblenden" else "anzeigen"}") })
            }
            if (showLow) items(low) { FindingCard(it) }
        }
    }
}

@Composable
fun FindingCard(f: Finding) {
    val ctx = LocalContext.current
    var open by remember { mutableStateOf(f.severity <= Severity.HIGH) }
    SectionCard {
        Column(Modifier.clickable { open = !open }, verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Pill(f.levelText, Svs.color(f.severity))
                Spacer(Modifier.width(8.dp))
                Text(f.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
            }
            if (open) {
                if (f.facts.isEmpty()) Body(f.detail)
                f.facts.forEach { (k, v) ->
                    Row { Text("$k: ", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold); Text(v, style = MaterialTheme.typography.bodySmall) }
                }
                if (f.factors.isNotEmpty()) {
                    Text("Score erhöht durch:", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    f.factors.forEach { Text("  $it", style = MaterialTheme.typography.bodySmall, color = Svs.color(f.severity)) }
                }
                if (f.neutral.isNotEmpty()) {
                    Text("Als unkritisch eingestuft:", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    f.neutral.forEach { Text("  ✓ $it", style = MaterialTheme.typography.bodySmall, color = Svs.Green) }
                }
                Text("Empfehlung: ${f.advice}", style = MaterialTheme.typography.bodySmall)
            }
        }
        if (open && f.action != FixAction.NONE) Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = { Actions.run(ctx, f.action, f.pkg) },
                colors = if (f.action == FixAction.UNINSTALL) ButtonDefaults.buttonColors(containerColor = Svs.Red) else ButtonDefaults.buttonColors(),
            ) {
                Text(
                    when (f.action) {
                        FixAction.UNINSTALL -> "Deinstallieren"
                        FixAction.ACCESSIBILITY -> "Bedienungshilfen öffnen"
                        FixAction.DEVICE_ADMIN -> "Geräteadministratoren"
                        FixAction.NOTIFICATION_ACCESS -> "Benachrichtigungszugriff"
                        FixAction.PRIVATE_DNS -> "Privates DNS einrichten"
                        FixAction.HOME_SETTINGS -> "Startbildschirm wählen"
                        FixAction.UPDATE_SETTINGS -> "Software-Update"
                        FixAction.DEV_SETTINGS -> "Entwickleroptionen"
                        FixAction.SECURITY_SETTINGS -> "Sicherheitseinstellungen"
                        else -> "App-Info öffnen"
                    },
                )
            }
            if (f.pkg != null && f.action != FixAction.APP_SETTINGS) OutlinedButton(onClick = { Actions.appSettings(ctx, f.pkg) }) { Text("App-Info") }
        }
    }
}
