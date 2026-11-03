package de.svs.security.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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
import de.svs.security.Actions
import de.svs.security.intel.Parsers
import de.svs.security.intel.ThreatIntel

@Composable
fun DataScreen(vm: AppViewModel, modifier: Modifier) {
    val ctx = LocalContext.current
    val st by ThreatIntel.status.collectAsState()
    val busy by vm.intelUpdating.collectAsState()
    val msg by vm.intelMessage.collectAsState()
    var mobileOnly by rememberSaveable { mutableStateOf(true) }
    val news = if (mobileOnly) st.news.filter { Parsers.isMobileRelevant(it) } else st.news

    LazyColumn(modifier.fillMaxWidth(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            SectionCard("Bedrohungsdaten in der App") {
                Body("Stand: ${fmtDateTime(st.lastUpdate)} (automatisch alle 24 Stunden)")
                Body("• ${st.families} Spionage-App-Familien mit ${st.packages} Paketnamen")
                Body("• ${st.certificates} Signatur-Zertifikate, ${st.hashes} APK-Fingerabdrücke")
                Body("• ${st.domains} gefährliche Webseiten (Malware, Phishing, Spionage-Server)")
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                msg?.let { Muted(it) }
                st.lastError?.let { Muted("Letzte Fehler:\n$it") }
                Button(onClick = { vm.updateIntel() }, enabled = !busy) { Text("Jetzt aktualisieren") }
            }
        }
        item {
            SectionCard("Quellen") {
                ThreatIntel.SOURCES.forEach { s ->
                    Column(Modifier.clickable { Actions.url(ctx, s.url) }) {
                        Text(s.title, fontWeight = FontWeight.SemiBold)
                        Muted(s.description)
                    }
                }
            }
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("BSI-Warnungen", style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                Text("nur Handy-relevant  ", style = MaterialTheme.typography.bodySmall)
                Switch(mobileOnly, { mobileOnly = it })
            }
        }
        items(news.take(80)) { n ->
            SectionCard {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Pill(n.severity.ifEmpty { "info" }, when (n.severity.lowercase()) { "kritisch" -> Brand.Red; "hoch" -> Brand.Amber; else -> Brand.Blue })
                    Spacer(Modifier.width(8.dp))
                    Muted(n.pubDate.take(16))
                }
                Text(n.title, fontWeight = FontWeight.SemiBold, modifier = Modifier.clickable { Actions.url(ctx, n.link) })
                Muted(n.description)
            }
        }
        if (news.isEmpty()) item { Muted("Keine passenden Meldungen – „Jetzt aktualisieren“ tippen.") }
    }
}
