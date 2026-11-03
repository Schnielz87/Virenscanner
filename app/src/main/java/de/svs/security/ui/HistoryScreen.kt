package de.svs.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import de.svs.security.Actions
import de.svs.security.history.LogEvent
import de.svs.security.history.Timeline

@Composable
fun HistoryScreen(vm: AppViewModel, modifier: Modifier) {
    val ctx = LocalContext.current
    val events by vm.timeline.collectAsState()
    val loading by vm.timelineLoading.collectAsState()
    val days by vm.timelineDays.collectAsState()
    var onlyAlerts by rememberSaveable { mutableStateOf(false) }
    var hideHome by rememberSaveable { mutableStateOf(true) }
    var access by rememberSaveable { mutableStateOf(Timeline.hasUsageAccess(ctx)) }

    LaunchedEffect(Unit) { vm.loadTimeline() }
    LifecycleResumeEffect(Unit) {
        val now = Timeline.hasUsageAccess(ctx)
        if (now != access) { access = now; vm.loadTimeline() }
        onPauseOrDispose {}
    }

    val shown = events.filter { (!onlyAlerts || it.alert) && (!hideHome || it.type != "HOME") }
    val grouped = shown.groupBy { AppViewModel.startOfDay(it.time) }.toSortedMap(compareByDescending { it })

    LazyColumn(modifier.fillMaxWidth(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (!access) item {
            SectionCard("Nutzungsdaten freigeben (wichtig)", Svs.Red) {
                Body("Damit die App rückwirkend zeigen kann, welche App wann geöffnet wurde, wann das Handy neu gestartet und entsperrt wurde, braucht sie den „Nutzungsdatenzugriff“. Android speichert diese Daten ca. 7–10 Tage – gestern Abend ist also noch sichtbar.")
                Button(onClick = { Actions.usageAccess(ctx) }) { Text("Zugriff erlauben") }
                Muted("In der Liste „SVS Security“ antippen und einschalten, dann zurückkehren.")
            }
        }
        item {
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                items(listOf(1 to "Heute", 2 to "Seit gestern", 3 to "3 Tage", 7 to "7 Tage", 30 to "30 Tage")) { (d, l) ->
                    FilterChip(selected = days == d, onClick = { vm.loadTimeline(d) }, label = { Text(l) })
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 4.dp)) {
                Switch(onlyAlerts, { onlyAlerts = it }); Text("  Nur Auffälliges", modifier = Modifier.width(140.dp))
                Switch(!hideHome, { hideHome = !it }); Text("  Startbildschirm")
            }
            if (loading) LinearProgressIndicator(Modifier.fillMaxWidth())
        }
        item { Summary(events) }
        grouped.forEach { (day, list) ->
            item { Text(fmtDay(day), style = MaterialTheme.typography.titleSmall, color = Svs.Red, fontWeight = FontWeight.Bold) }
            items(list) { EventRow(it) }
        }
        if (!loading && shown.isEmpty()) item { Muted("Keine Einträge im gewählten Zeitraum.") }
        item {
            Muted("Hinweis: Android protokolliert nur, welche App wann aktiv war – nicht, welche Person das Handy bedient hat. Wurde vorher „Handy entsperrt“ angezeigt, hatte die Person die PIN/den Fingerabdruck. Das eigene Protokoll dieser App (Daten gelöscht, Widgets/Startbildschirm, Neustarts, neue Rechte) beginnt mit der Installation.")
        }
    }
}

@Composable
private fun Summary(ev: List<LogEvent>) {
    val boots = ev.count { it.type == "BOOT" || it.type == "SHUTDOWN" || it.type == "SAFE_MODE" }
    val safe = ev.count { it.type == "SAFE_MODE" }
    val installs = ev.filter { it.type == "INSTALL" }
    val unknownInstalls = installs.count { it.alert }
    val settings = ev.count { it.pkg in Timeline.SETTINGS_PKGS }
    val cleared = ev.filter { it.type == "DATA_CLEARED" }
    val pkgInstaller = ev.count { it.pkg in Timeline.INSTALLER_PKGS }
    val unlocks = ev.count { it.type == "UNLOCK" }
    SectionCard("Zusammenfassung des Zeitraums") {
        Body("• $unlocks× entsperrt, $boots Neustart-/Ausschalt-Ereignisse${if (safe > 0) " (davon $safe× abgesicherter Modus!)" else ""}")
        Body("• ${installs.size} App-Installationen, davon $unknownInstalls aus unbekannter Quelle")
        Body("• $pkgInstaller× App-Installationsprogramm geöffnet (APK-Installation)")
        Body("• $settings× Einstellungen geöffnet")
        if (cleared.isNotEmpty()) Body("• App-Daten gelöscht: ${cleared.joinToString { it.title.removePrefix("App-Daten gelöscht: ") }}")
        if (unknownInstalls == 0 && pkgInstaller == 0 && safe == 0) Muted("Keine Installation aus unbekannter Quelle im Zeitraum – ein Trojaner wurde in diesem Zeitraum demnach nicht installiert.")
    }
}

@Composable
private fun EventRow(e: LogEvent) {
    Column(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.Top) {
            Text(fmtTime(e.time), style = MaterialTheme.typography.labelMedium, modifier = Modifier.width(72.dp), color = if (e.alert) Svs.Red else Svs.Grey)
            Column(Modifier.weight(1f)) {
                Text(e.title, style = MaterialTheme.typography.bodyMedium, fontWeight = if (e.alert) FontWeight.Bold else FontWeight.Normal, color = if (e.alert) Svs.Red else MaterialTheme.colorScheme.onSurface)
                if (e.detail.isNotEmpty()) Muted(e.detail)
                e.pkg?.let { Muted(it) }
            }
        }
        HorizontalDivider(Modifier.padding(top = 6.dp))
    }
}
