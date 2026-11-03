package de.svs.security.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import de.svs.security.Actions
import de.svs.security.vpn.WebShieldService
import kotlinx.coroutines.delay

@Composable
fun ProtectScreen(vm: AppViewModel, modifier: Modifier, shared: String?, enableShield: () -> Unit, consumeShared: () -> Unit) {
    val ctx = LocalContext.current
    var shieldOn by remember { mutableStateOf(WebShieldService.isEnabled(ctx)) }
    var tick by remember { mutableIntStateOf(0) }
    var link by remember { mutableStateOf(shared.orEmpty()) }
    val linkResult by vm.linkResult.collectAsState()

    LaunchedEffect(shared) { if (!shared.isNullOrBlank()) { link = shared; vm.checkLink(shared); consumeShared() } }
    LifecycleResumeEffect(Unit) { shieldOn = WebShieldService.isEnabled(ctx); tick++; onPauseOrDispose {} }
    LaunchedEffect(shieldOn) { repeat(3) { delay(700); shieldOn = WebShieldService.isEnabled(ctx); tick++ } }

    val notif = Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    LazyColumn(modifier.fillMaxWidth(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            SectionCard("Web-Schutz (blockiert Betrugsseiten)", if (shieldOn) Svs.Green else Svs.Grey) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Body(if (shieldOn) "Aktiv – gefährliche Seiten werden gesperrt" else "Aus")
                        Muted("Bisher blockiert: ${WebShieldService.blockedCount(ctx)} Aufrufe")
                    }
                    Switch(checked = shieldOn, onCheckedChange = { on ->
                        if (on) enableShield() else WebShieldService.stop(ctx)
                        shieldOn = on
                    })
                }
                Muted("Prüft jede Webseiten-Adresse gegen die täglich aktualisierten Listen (Malware, Phishing, Spionage-Server). Technisch ein lokales VPN nur für Adressabfragen: dein Datenverkehr wird nicht mitgelesen und verlässt das Handy wie bisher. Das Schlüssel-Symbol oben in der Statusleiste ist normal.")
                OutlinedButton(onClick = { Actions.vpnSettings(ctx) }) { Text("„Dauerhaft aktiv“ einstellen (empfohlen)") }
                Muted("In den VPN-Einstellungen bei „SVS Web-Schutz“ auf ⚙ tippen und „Durchgehend aktives VPN“ einschalten – dann startet der Schutz auch nach einem Neustart.")
            }
        }
        item {
            SectionCard("Überwachung & Warnungen", if (notif) Svs.Green else Svs.Amber) {
                Body("Läuft automatisch im Hintergrund:")
                Body("• stündlich: neue Apps, neue Bedienungshilfen, Geräteadministratoren, Wechsel des Startbildschirms oder der SMS-App")
                Body("• sofort: App-Daten gelöscht (z. B. Startbildschirm → Widgets weg), App deinstalliert, Neustart im abgesicherten Modus, neu installierte App mit Schadsoftware-Merkmalen")
                Body("• täglich: neue Bedrohungsdaten laden, Vollprüfung, Update-Prüfung")
                if (!notif) Muted("Benachrichtigungen sind für SVS Security ausgeschaltet – Warnungen erscheinen dann nur in der App.")
                if (!notif) OutlinedButton(onClick = { Actions.appSettings(ctx, ctx.packageName) }) { Text("Benachrichtigungen erlauben") }
            }
        }
        item {
            SectionCard("Link prüfen") {
                Muted("Link einfügen oder in einer anderen App über „Teilen → SVS Security“ senden.")
                OutlinedTextField(link, { link = it }, label = { Text("https://…") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                Button(onClick = { vm.checkLink(link) }, enabled = link.isNotBlank()) { Text("Prüfen") }
                linkResult?.let { (host, threat) ->
                    if (threat == null) Body("✅ $host ist in keiner Gefahrenliste. (Garantie für Seriosität ist das nicht – bei Zahlungsaufforderungen immer skeptisch bleiben.)")
                    else {
                        Text("⛔ $host ist als GEFÄHRLICH gelistet: $threat", color = Svs.Red)
                        val allowed = WebShieldService.isAllowed(ctx, host)
                        TextButton(onClick = { WebShieldService.setAllowed(ctx, host, !allowed); tick++ }) {
                            Text(if (allowed) "Ausnahme wieder entfernen" else "Trotzdem zulassen (Ausnahme)")
                        }
                    }
                }
            }
        }
        item {
            SectionCard("Zusätzlich empfohlen") {
                Body("1. Privates DNS „dns.quad9.net“ – blockiert Schadseiten auch ohne diese App.")
                OutlinedButton(onClick = { Actions.privateDns(ctx) }) { Text("Privates DNS einrichten") }
                Body("2. Samsung Internet absichern: ☰ → Einstellungen → Datenschutz und Sicherheit → „Pop-ups blockieren“ und „Vor schädlichen Websites warnen“ einschalten; unter „Seiten und Downloads“ Benachrichtigungen von Webseiten nicht erlauben.")
                OutlinedButton(onClick = { Actions.appSettings(ctx, "com.sec.android.app.sbrowser") }) { Text("Samsung Internet App-Info") }
                Body("3. Startbildschirm sichern: Einstellungen → Konten und Sicherung → Daten sichern → „Startbildschirm“ aktivieren. Dann lassen sich Widgets und Anordnung nach einem Zurücksetzen wiederherstellen.")
                OutlinedButton(onClick = { Actions.open(ctx, android.content.Intent(android.provider.Settings.ACTION_SETTINGS)) }) { Text("Einstellungen öffnen") }
                Body("4. Google Play Protect eingeschaltet lassen (Play Store → Profilbild → Play Protect).")
            }
        }
        val allow = WebShieldService.allowlist(ctx).also { tick }
        if (allow.isNotEmpty()) item {
            SectionCard("Ausnahmen") {
                allow.sorted().forEach { h ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Body(h); TextButton(onClick = { WebShieldService.setAllowed(ctx, h, false); tick++ }) { Text("entfernen") }
                    }
                }
            }
        }
    }
}
