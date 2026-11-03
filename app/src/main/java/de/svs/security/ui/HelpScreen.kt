package de.svs.security.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import de.svs.security.Actions
import de.svs.security.history.EventLog
import de.svs.security.update.UpdateChecker

@Composable
fun HelpScreen(vm: AppViewModel, modifier: Modifier) {
    val ctx = LocalContext.current
    val status by vm.updateStatus.collectAsState()
    val avail by vm.update.collectAsState()
    val busy by vm.updateBusy.collectAsState()

    LazyColumn(modifier.fillMaxWidth(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            SectionCard("Was war die Meldung „Innenministerium – Abteilung für Cyberkriminalität“?", Svs.Red) {
                Body("Eine bekannte Betrugsmasche („Polizei-“ bzw. „BKA-Trojaner“ für den Browser). Eine Webseite – meist über Werbung oder einen Tippfehler-Link geöffnet – zeigt per JavaScript immer wieder dieselbe Meldung an, sodass sich der Tab scheinbar nicht schließen lässt.")
                Body("• Behörden sperren keine Handys und fordern nie Geld per Sofortüberweisung auf ein Privatkonto (hier „Andrzej Stawski“).")
                Body("• Die Seite hatte KEINEN Zugriff auf dein Handy, deine Dateien oder Fotos. Sie lief nur im Browser.")
                Body("• Das Löschen von Cache/Daten von Samsung Internet war richtig und hat die Seite entfernt.")
                Body("• Auf keinen Fall zahlen. Falls doch gezahlt: sofort die Bank anrufen (Rückruf der Überweisung) und Anzeige erstatten.")
            }
        }
        item {
            SectionCard("Was jetzt tun?", Svs.Amber) {
                Body("1. In dieser App „Prüfen“ → „Jetzt vollständig prüfen“. Kritische oder hohe Befunde zuerst beheben.")
                Body("2. Unter „Verlauf“ den Nutzungsdatenzugriff erlauben und „Seit gestern“ ansehen: Neustarts, abgesicherter Modus, geöffnete Einstellungen und Installationen werden dort angezeigt.")
                Body("3. Web-Schutz unter „Schutz“ einschalten.")
                Body("4. Anzeige erstatten (online möglich) – Screenshot der Meldung mit IBAN und Namen beilegen. Das hilft, das Empfängerkonto sperren zu lassen.")
                OutlinedButton(onClick = { Actions.url(ctx, "https://www.polizei-bw.de/onlinewache/") }) { Text("Onlinewache Polizei BW") }
                OutlinedButton(onClick = { Actions.url(ctx, "https://www.polizei-beratung.de/themen-und-tipps/gefahren-im-internet/") }) { Text("Infos der Polizei zu Internetbetrug") }
            }
        }
        item {
            SectionCard("Warum sind Kalender-, Wetter-, Notiz- und Edelmetall-Widgets weg?", Svs.Blue) {
                Body("Das Löschen von Cache/Daten des Browsers entfernt keine Widgets. Typische Ursachen, wenn mehrere Widgets gleichzeitig verschwinden:")
                Body("• Abgesicherter Modus: Wer beim Neustart (z. B. um die Meldung loszuwerden) die Leiser-Taste hält, startet den abgesicherten Modus. Android entfernt dabei die Widgets aller nicht vorinstallierten Apps dauerhaft vom Startbildschirm. Erkennbar am Schriftzug „Abgesicherter Modus“ unten links.")
                Body("• Falsche App zurückgesetzt: Wurden unter Einstellungen → Apps versehentlich die Daten von „One UI Home“ (Startbildschirm) statt von Samsung Internet gelöscht, setzt sich der Startbildschirm auf Werkszustand zurück – alle Widgets und die Anordnung sind weg.")
                Body("• Gerätewartung / „Optimieren“ oder ein anderer Startbildschirm (Launcher) wurde aktiviert.")
                Body("Die Apps selbst (Kalender, Wetter, Notizen, Tracker) und ihre Daten sind in all diesen Fällen noch da – nur die Widgets fehlen.")
                Body("Wiederherstellen: Lange auf eine freie Stelle des Startbildschirms drücken → „Widgets“ → gewünschtes Widget auswählen und platzieren. Falls ein Backup existiert: Einstellungen → Konten und Sicherung → Daten wiederherstellen → „Startbildschirm“.")
                Body("Ab jetzt protokolliert diese App solche Vorgänge (Daten gelöscht, abgesicherter Modus, Launcher-Wechsel) und warnt sofort.")
            }
        }
        item {
            SectionCard("Grenzen der App (ehrlich)") {
                Body("Android lässt Apps aus Sicherheitsgründen nicht in andere Apps hineinsehen. Die App erkennt bekannte Schad- und Spionage-Apps, gefährliche Rechte, Installationen aus unbekannten Quellen, verdächtige Rollen und Einstellungen. Ein komplett neuer, unbekannter Trojaner kann – wie bei jedem Virenscanner – unentdeckt bleiben.")
                Body("Welche Person das Handy bedient hat, kann Android nicht aufzeichnen – nur welche App wann aktiv war und ob das Handy entsperrt wurde.")
            }
        }
        item {
            SectionCard("Update") {
                Body("Installierte Version: ${UpdateChecker.currentVersion(ctx)}")
                Muted("Die App prüft täglich automatisch auf neue Versionen.")
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                status?.let { Muted(it) }
                if (avail != null) Button(onClick = { vm.downloadAndInstall() }, enabled = !busy) { Text("Update jetzt installieren") }
                else Button(onClick = { vm.checkUpdate(install = true) }, enabled = !busy) { Text("Nach Updates suchen") }
                OutlinedButton(onClick = { UpdateChecker.openInBrowser(ctx) }) { Text("Download-Seite im Browser öffnen") }
            }
        }
        item {
            SectionCard("Protokoll") {
                Muted("Das eigene Protokoll enthält ${EventLog.all(ctx).size} Einträge und bleibt nur auf diesem Handy.")
                OutlinedButton(onClick = { EventLog.clear(ctx); vm.loadTimeline() }) { Text("Protokoll löschen") }
            }
        }
    }
}
