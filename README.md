# SVS Security – Sicherheits-App für Android

Virenscanner, rückwirkender Verlauf, Web-Schutz und Warnungen für Samsung-/Android-Handys.
Entstanden nach einer Browser-Sperrmeldung („Innenministerium – Abteilung für Cyberkriminalität“,
Zahlung von 610 € gefordert) und danach verschwundenen Widgets.

**Download (neueste Version):**
[`SVS-Security.apk`](https://github.com/Schnielz87/Virenscanner/releases/download/neueste-version/SVS-Security.apk)
(GitHub → Releases → „SVS Security v1.0.x“, ohne Anmeldung)

## Funktionen

| Tab | Inhalt |
|---|---|
| **Prüfen** (a) | Alle Apps werden geprüft: Paketname, Signatur-Zertifikat und SHA-256-Fingerabdruck gegen die Bedrohungsdaten; Herkunft (Play/Galaxy Store oder APK aus Browser/Messenger); versteckte Apps ohne Symbol; Bedienungshilfen, Geräteadministratoren, Benachrichtigungszugriff, Overlay-Recht; fremder Startbildschirm, fremde SMS-App. Geräte-Checks: abgesicherter Modus, Bildschirmsperre, USB-Debugging, Alter des Sicherheitspatches, Root, Web-Filter, „unbekannte Apps installieren“. Jeder Befund mit Erklärung und Knopf zur passenden Einstellung. |
| **Gesamtübersicht** | Auf „Prüfen“ → „Gesamtübersicht erstellen“: ein Bericht mit Gesamtbewertung, allen Befunden (Schwere, Paket, Befund, Empfehlung), Gerätestatus, Apps mit besonderen Rechten, Apps aus unbekannter Quelle (mit SHA-256), Installationen der letzten 14 Tage, auffälligen Ereignissen der letzten 7 Tage und Stand der Bedrohungsdaten. **Kopieren**, **Teilen** oder als `.txt` **speichern**. |
| **Verlauf** (b) | Rückwirkende Chronik: welche App wann aktiv war, Entsperren, Neustarts/Ausschalten (Android-Nutzungsstatistik, ca. 7–10 Tage), Installationen und Updates aller Apps mit Quelle (unbegrenzt), dazu das eigene Protokoll (Daten gelöscht, Deinstallationen, abgesicherter Modus, neue Rechte, blockierte Seiten). Zusammenfassung je Zeitraum. |
| **Schutz** (c) | Web-Schutz: lokales DNS-VPN blockiert Malware-/Phishing-/Spionage-Domains, bevor der Browser sie lädt. Überwachung im Hintergrund mit Warnungen. Link-Prüfung (auch über „Teilen“). Empfehlungen (Privates DNS, Samsung Internet, Startbildschirm-Backup). |
| **Daten** | Täglich aktualisierte Bedrohungsdaten mit Stand und Umfang, BSI-Warnungen (filterbar auf Handy-relevante Meldungen). |
| **Hilfe** | Erklärung der Betrugsmasche, Vorgehen (Anzeige, Bank), Ursachen und Wiederherstellung verschwundener Widgets, Grenzen der App, **Update**. |

### Warnungen (Benachrichtigungen)

* sofort: App-Daten gelöscht (z. B. Startbildschirm → Widgets weg), App deinstalliert, Neustart im abgesicherten Modus,
  neu installierte App mit Schadsoftware-Merkmalen, blockierte gefährliche Webseite
* stündlich: neue App (besonders aus unbekannter Quelle), neue Bedienungshilfe, neuer Geräteadministrator,
  Benachrichtigungszugriff, Wechsel von Startbildschirm- oder SMS-App
* täglich: neue Befunde der Vollprüfung, neue App-Version

### Bedrohungsdaten (täglich, ohne API-Schlüssel)

| Quelle | Inhalt |
|---|---|
| [Echap stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) | Paketnamen, Zertifikate, APK-Hashes und Server von Spionage-Apps |
| [URLhaus](https://urlhaus.abuse.ch/) über [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter) | Webseiten, die Schadsoftware verteilen |
| [phishing-filter](https://gitlab.com/malware-filter/phishing-filter) (OpenPhish, PhishTank, IPThreat) | Phishing-/Betrugsseiten |
| [BSI WID](https://wid.cert-bund.de/portal/wid/securityadvisory) | Sicherheitswarnungen des BSI |

Ein Grundstock liegt in `app/src/main/assets/intel/` – die App funktioniert damit auch offline.

## Update-Funktion

Wie bei den anderen Apps: Jeder Push baut per GitHub Actions eine neue APK
(`versionName 1.0.<Lauf-Nr. + 10>`) und ersetzt das Release `neueste-version`. Die App prüft täglich
und unter *Hilfe → Update*, lädt die APK und öffnet den Android-Installer. Alle APKs sind mit
`app/signing/sideload.jks` signiert → Update ohne Datenverlust.

Das Repository ist öffentlich, daher funktionieren Update-Prüfung und Download ohne GitHub-Konto
(Einstellung: `REPO`/`TAG` in [`UpdateChecker.kt`](app/src/main/java/de/svs/security/update/UpdateChecker.kt)).

**Umstieg von Version 1.0.1/1.0.2** (aus dem privaten Repo SVS-APP): diese Versionen suchen Updates noch
im alten Repo. Einmalig die APK über den Link oben installieren – danach kommen alle Updates über die App.

## Grenzen

Android isoliert Apps voneinander; ohne Root kann keine App in andere Apps hineinsehen oder
Widget-Änderungen fremder Launcher auslesen. Erkannt werden bekannte Schad-/Spionage-Apps und
typische Trojaner-Merkmale. Wer das Handy bedient hat, protokolliert Android nicht – nur welche App
wann aktiv war und ob entsperrt wurde.

## Bauen

```bash
./gradlew testDebugUnitTest assembleRelease
```
