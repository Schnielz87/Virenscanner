# Handywächter – Sicherheits-App für Android

Virenscanner, rückwirkender Verlauf, Web-Schutz und Warnungen für Samsung-/Android-Handys.
Entstanden nach einer Browser-Sperrmeldung („Innenministerium – Abteilung für Cyberkriminalität“,
Zahlung von 610 € gefordert) und danach verschwundenen Widgets.

**Download (neueste Version):**
[`Handywaechter.apk`](https://github.com/Schnielz87/Virenscanner/releases/download/neueste-version/Handywaechter.apk)
(GitHub → Releases → „Handywächter v1.0.x“, ohne Anmeldung)

## Funktionen

| Tab | Inhalt |
|---|---|
| **Prüfen** (a) | Alle Apps werden geprüft: Paketname, Signatur-Zertifikat und SHA-256-Fingerabdruck gegen die Bedrohungsdaten; Herkunft (Play/Galaxy Store oder APK aus Browser/Messenger); versteckte Apps ohne Symbol; Bedienungshilfen, Geräteadministratoren, Benachrichtigungszugriff, Overlay-Recht; fremder Startbildschirm, fremde SMS-App. Geräte-Checks: abgesicherter Modus, Bildschirmsperre, USB-Debugging, Alter des Sicherheitspatches, Root, Web-Filter, „unbekannte Apps installieren“. Jeder Befund mit Erklärung und Knopf zur passenden Einstellung. |
| **Gesamtübersicht** | Auf „Prüfen“ → „Gesamtübersicht erstellen“: ein Bericht mit Gesamtbewertung, allen Befunden (Schwere, Paket, Befund, Empfehlung), Gerätestatus, Apps mit besonderen Rechten, Apps aus unbekannter Quelle (mit SHA-256), Installationen der letzten 14 Tage, auffälligen Ereignissen der letzten 7 Tage und Stand der Bedrohungsdaten. **Kopieren**, **Teilen** oder als `.txt` **speichern**. |
| **Verlauf** (b) | Rückwirkende Chronik: welche App wann aktiv war, Entsperren, Neustarts/Ausschalten (Android-Nutzungsstatistik, ca. 7–10 Tage), Installationen und Updates aller Apps mit Quelle (unbegrenzt), dazu das eigene Protokoll (Daten gelöscht, Deinstallationen, abgesicherter Modus, neue Rechte, blockierte Seiten). Zusammenfassung je Zeitraum. |
| **Schutz** (c) | Web-Schutz: lokales DNS-VPN blockiert Malware-/Phishing-/Spionage-Domains, bevor der Browser sie lädt. Überwachung im Hintergrund mit Warnungen. Link-Prüfung (auch über „Teilen“). Empfehlungen (Privates DNS, Samsung Internet, Startbildschirm-Backup). |
| **Daten** | Täglich aktualisierte Bedrohungsdaten mit Stand und Umfang, BSI-Warnungen (filterbar auf Handy-relevante Meldungen). |
| **Diagnose** | Bewertet ALLE installierten Apps (auch unauffällige): Score, Faktoren, „unkritisch, weil …“, Herkunft, Hersteller-Signatur, Sonderrechte und **Entfernen-Risiko** (Systemkritisch / In Benutzung / Systemkomponente / Herstellerkomponente / Nutzer-App). Filter (Treffer, Ohne Symbol, Hersteller, Unbekannte Quelle, Nicht entfernen). Export als JSON (`Handywaechter-Diagnose_….json`) zum Speichern, Teilen oder Kopieren – zur Auswertung von Fehlalarmen. |
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

## Risikobewertung (Risk Score)

Jede App wird mehrstufig bewertet (`scan/Identity.kt` → `scan/RiskRules.kt`, Gewichte zentral in `scan/RiskConfig.kt`):

1. **Identität & Herkunft:** Installationsquelle (Store, Herstellerkomponente, Systemkomponente, APK, andere App, unbekannt),
   vorinstalliert oder nachträglich. **Herstellerkomponente** nur, wenn das Signatur-Zertifikat mit dem einer vorinstallierten
   App desselben Herstellers übereinstimmt (bzw. Plattform-Signatur) – Paketpräfixe wie `com.samsung.*` allein zählen nicht.
2. **Sonderrechte:** Bedienungshilfe 25, Geräteadministrator 25, Benachrichtigungen 15, Einblenden 12, Apps installieren 10,
   VPN 10, SMS 10 … (bei bestätigter Identität 30 %).
3. **Kombinationen:** kein Symbol + unbekannte Quelle + Bedienungshilfe +25, Einblenden + Bedienungshilfe +20,
   unbekannte Quelle + Geräteadministrator +40, u. a.
4. **Score 0–100:** 0–19 Unauffällig · 20–39 Geringes Risiko · 40–59 Prüfen · 60–79 Verdächtig · 80–100 Hohes Risiko.

Ein fehlendes App-Symbol zählt nur **3 Punkte** (bei Sprachpaketen, TTS-Stimmen, Plugins, Zubehör-Modulen: 0, mit Begründung).
Die App spricht nur bei Übereinstimmung mit Bedrohungsdaten von einer „bekannten Spionage-App“, sonst von
„Verdächtige App“, „Erhöhtes Risiko“ oder „Manuelle Prüfung empfohlen“.

### Prüfung im Hintergrund

„Jetzt vollständig prüfen“ startet die Prüfung als Hintergrundauftrag (WorkManager, Vordergrunddienst mit
Fortschritts-Benachrichtigung). Sie läuft weiter, wenn die App minimiert oder geschlossen wird; am Ende kommt
eine Benachrichtigung mit dem Ergebnis.

## Update-Funktion

Wie bei den anderen Apps: Jeder Push baut per GitHub Actions eine neue APK
(`versionName 1.0.<Lauf-Nr. + 10>`) und ersetzt das Release `neueste-version`. Die App prüft täglich
und unter *Hilfe → Update*, lädt die APK und öffnet den Android-Installer. Alle APKs sind mit
`app/signing/sideload.jks` signiert. Die interne Kennung `de.svs.security` bleibt bewusst unverändert –
sonst wäre jede neue Version eine neue App und die bisherige ließe sich nicht aktualisieren → Update ohne Datenverlust.

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
