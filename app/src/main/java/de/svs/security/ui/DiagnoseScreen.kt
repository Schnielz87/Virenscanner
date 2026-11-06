package de.svs.security.ui

import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
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
import de.svs.security.diag.DiagEntry
import de.svs.security.diag.Diagnostics
import de.svs.security.diag.RemovalRisk
import de.svs.security.scan.RiskConfig

private enum class DiagFilter(val label: String, val test: (DiagEntry) -> Boolean) {
    HITS("Treffer", { it.a.score >= RiskConfig.SHOW_FROM }),
    ALL("Alle", { true }),
    NO_ICON("Ohne Symbol", { !it.a.app.hasLauncher }),
    VENDOR("Hersteller", { it.a.app.vendor != null }),
    UNKNOWN("Unbekannte Quelle", { e -> e.a.factors.any { "nicht aus Store/Hersteller/System" in it } }),
    CRITICAL("Nicht entfernen", { it.removal == RemovalRisk.SYSTEM_CRITICAL || it.removal == RemovalRisk.IN_USE }),
}

/** Diagnose: zeigt fuer JEDE App, wie sie bewertet wurde – und exportiert alles als Datei zur Auswertung. */
@Composable
fun DiagnoseScreen(vm: AppViewModel, modifier: Modifier, save: () -> Unit) {
    val ctx = LocalContext.current
    val diag by vm.diag.collectAsState()
    val busy by vm.diagBusy.collectAsState()
    var filter by rememberSaveable { mutableStateOf(DiagFilter.HITS) }

    LazyColumn(modifier.fillMaxWidth(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            SectionCard("Diagnose / Prüfprotokoll") {
                Body("Bewertet ALLE installierten Apps (auch unauffällige) und zeigt je App: Score, Gründe, Herkunft, Hersteller-Signatur und ob Entfernen gefahrlos ist. Die Datei kannst du zur Auswertung weitergeben.")
                Muted("Enthält die Liste deiner installierten Apps – keine Nachrichten, Fotos oder Passwörter.")
                if (busy != null) { LinearProgressIndicator(Modifier.fillMaxWidth()); Muted(busy ?: "") }
                Button(onClick = { vm.buildDiag() }, enabled = busy == null, modifier = Modifier.fillMaxWidth()) {
                    Text(if (diag == null) "Diagnose erstellen" else "Diagnose neu erstellen")
                }
                if (diag != null) Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = save) { Text("Speichern") }
                    OutlinedButton(onClick = {
                        val json = vm.diagJson() ?: return@OutlinedButton
                        ctx.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain")
                            .putExtra(Intent.EXTRA_SUBJECT, "Handywächter – Diagnose").putExtra(Intent.EXTRA_TEXT, json), "Diagnose teilen"))
                    }) { Text("Teilen") }
                    OutlinedButton(onClick = {
                        val json = vm.diagJson() ?: return@OutlinedButton
                        runCatching { Actions.copy(ctx, json) }
                            .onSuccess { Toast.makeText(ctx, "Kopiert (${json.length / 1024} KB)", Toast.LENGTH_SHORT).show() }
                            .onFailure { Toast.makeText(ctx, "Zu groß für die Zwischenablage – bitte „Speichern“ nutzen", Toast.LENGTH_LONG).show() }
                    }) { Text("Kopieren") }
                }
            }
        }
        val d = diag ?: return@LazyColumn
        item {
            SectionCard("Zusammenfassung") {
                Diagnostics.summary(d.entries).forEach { (k, v) ->
                    Row { Text(k, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f)); Text("$v", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold) }
                }
            }
        }
        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(DiagFilter.entries) { f ->
                    FilterChip(selected = filter == f, onClick = { filter = f }, label = { Text("${f.label} (${d.entries.count(f.test)})") })
                }
            }
        }
        val list = d.entries.filter(filter.test).sortedWith(compareByDescending<DiagEntry> { it.a.score }.thenBy { it.a.app.label.lowercase() })
        items(list, key = { it.a.app.pkg }) { DiagRow(it) }
        if (list.isEmpty()) item { Muted("Keine Apps in dieser Ansicht.") }
    }
}

@Composable
private fun DiagRow(e: DiagEntry) {
    var open by remember { mutableStateOf(false) }
    val a = e.a
    val sevColor = if (a.score >= RiskConfig.SHOW_FROM) Brand.color(a.level.severity) else Brand.Green
    val removalColor = when (e.removal) {
        RemovalRisk.SYSTEM_CRITICAL -> Brand.Red
        RemovalRisk.IN_USE, RemovalRisk.SYSTEM -> Brand.Amber
        RemovalRisk.VENDOR_COMPONENT -> Brand.Blue
        RemovalRisk.USER_APP -> Brand.Grey
    }
    SectionCard {
        Column(Modifier.clickable { open = !open }, verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Pill("${a.score}", sevColor)
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(a.app.label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Muted(a.app.pkg)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Pill(a.level.label, sevColor)
                Pill(e.removal.label, removalColor)
            }
            if (open) {
                kv("Bewertung", Diagnostics.verdict(e))
                kv("Identität", a.identity)
                kv("Art", a.kind.label)
                kv("Quelle", a.app.installSource.label + (a.app.installer?.let { " ($it)" } ?: ""))
                kv("App-Symbol", if (a.app.hasLauncher) "ja" else "nein")
                a.app.certSubject?.let { kv("Signiert von", it) }
                kv("Sonderrechte", a.rights.ifEmpty { listOf("keine") }.joinToString(", "))
                if (e.inUse.isNotEmpty()) kv("In Benutzung als", e.inUse.joinToString(", "))
                if (a.factors.isNotEmpty()) {
                    Text("Score-Faktoren:", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    a.factors.forEach { Text("  $it", style = MaterialTheme.typography.bodySmall, color = sevColor) }
                }
                if (a.neutral.isNotEmpty()) {
                    Text("Unkritisch, weil:", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
                    a.neutral.forEach { Text("  ✓ $it", style = MaterialTheme.typography.bodySmall, color = Brand.Green) }
                }
                Text("Entfernen: ${e.removal.advice}", style = MaterialTheme.typography.bodySmall, color = removalColor)
            }
        }
    }
}

@Composable
private fun kv(k: String, v: String) = Row {
    Text("$k: ", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)
    Text(v, style = MaterialTheme.typography.bodySmall)
}
