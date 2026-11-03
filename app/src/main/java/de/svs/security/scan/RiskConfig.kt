package de.svs.security.scan

/**
 * Zentrale Gewichtung der Risikobewertung (Punkte, Summe wird auf 0–100 begrenzt).
 * Jede Zahl ist begruendet; Aenderungen nur hier vornehmen.
 */
object RiskConfig {

    // ---- Stufen ----
    const val LEVEL_LOW = 20        // ab hier: Geringes Risiko
    const val LEVEL_CHECK = 40      // ab hier: Prüfen
    const val LEVEL_SUSPICIOUS = 60 // ab hier: Verdächtig
    const val LEVEL_HIGH = 80       // ab hier: Hohes Risiko

    /** Ab diesem Score wird eine App als Treffer in der Liste angezeigt. */
    const val SHOW_FROM = LEVEL_LOW

    // ---- Indikator-Treffer (Bedrohungsdaten) ----
    /** APK-Fingerabdruck identisch mit bekannter Spionage-App: eindeutig. */
    const val IOC_HASH = 100
    /** Signatur-Zertifikat einer bekannten Spionage-App: praktisch eindeutig (Schluessel gehoert dem Anbieter). */
    const val IOC_CERT = 100
    /** Nur der Paketname stimmt ueberein: stark, aber Namen koennen zufaellig gleich sein. */
    const val IOC_PACKAGE = 60

    // ---- Herkunft ----
    /** Nicht aus Store/Hersteller/System: die haeufigste Voraussetzung fuer Schad-Apps, allein aber kein Beweis. */
    const val UNKNOWN_SOURCE = 15
    /** Zusaetzlich ueber Browser/Messenger erhalten (typischer Verbreitungsweg von Betrugs-APKs). */
    const val VIA_BROWSER_OR_MESSENGER = 5
    /** Kein App-Symbol: bewusst minimal – Sprachpakete, Plugins, Dienste haben nie eines. */
    const val NO_LAUNCHER_ICON = 3
    /** Zufaellig wirkender/kein lesbarer Name. */
    const val UNUSUAL_NAME = 6
    /** Gibt sich als System-/Herstellerkomponente aus, Signatur passt nicht. */
    const val IMPERSONATION = 15
    /** In den letzten 14 Tagen installiert (nur in Kombination relevant, siehe COMBO_RECENT). */
    const val RECENT_DAYS = 14

    // ---- Sonderrechte ----
    /** Bildschirm lesen und bedienen: Haupthebel fuer Fernsteuerung. */
    const val ACCESSIBILITY = 25
    /** Sperren/Loeschen, Deinstallationsschutz. */
    const val DEVICE_ADMIN = 25
    /** Fenster ueber anderen Apps (gefaelschte Masken). */
    const val OVERLAY = 12
    /** Liest alle Benachrichtigungen (TANs, Chats). */
    const val NOTIFICATION_LISTENER = 15
    /** Darf selbst weitere Apps installieren. */
    const val INSTALL_PACKAGES = 10
    /** Bringt einen VPN-Dienst mit (kann Datenverkehr umleiten). */
    const val VPN_SERVICE = 10
    /** Standard-SMS-App ohne System-Herkunft. */
    const val DEFAULT_SMS = 15
    /** Fremder Startbildschirm. */
    const val FOREIGN_LAUNCHER = 20
    const val SMS = 10
    const val PHONE = 6
    const val CONTACTS = 4
    const val MICROPHONE = 5
    const val CAMERA = 4
    const val LOCATION = 3
    const val BACKGROUND_LOCATION = 6
    /** Startet nach dem Einschalten automatisch (Persistenz). */
    const val AUTOSTART = 3

    // ---- Kombinationen (zusaetzlich) ----
    /** Kein Symbol + unbekannte Quelle + Bedienungshilfe: klassisches Muster versteckter Fernsteuerung. */
    const val COMBO_HIDDEN_ACCESSIBILITY = 25
    /** Einblenden + Bedienungshilfe: gefaelschte Masken + automatische Eingaben. */
    const val COMBO_OVERLAY_ACCESSIBILITY = 20
    /** Unbekannte Quelle + Geraeteadministrator: typisches Muster von Sperr-/Erpressungs-Apps. */
    const val COMBO_UNKNOWN_ADMIN = 40
    /** Kuerzlich nachinstalliert + ungewoehnlicher Name + weitreichendes Sonderrecht. */
    const val COMBO_RECENT_ODD_POWERFUL = 15
    /** Internet/Webseiten + Bedienungshilfe oder Einblenden, unbekannte Quelle. */
    const val COMBO_WEB_POWERFUL = 10
    /** Unbekannte Quelle + mindestens 3 Spionage-Rechte (Mikro, Kamera, Kontakte, Anrufliste, Standort). */
    const val COMBO_SPY_PERMS = 10

    // ---- Daempfung bei bestaetigter Identitaet ----
    /**
     * Rechte von signaturgeprueften Hersteller- bzw. vorinstallierten Komponenten zaehlen nur zu 30 %:
     * Samsung/Google liefern legitime Bedienungshilfen, Geraeteadministratoren (z. B. „Mein Gerät finden“)
     * und Overlays mit. Erst eine Haeufung mehrerer Sonderrechte fuehrt dann zu einem Treffer.
     */
    const val TRUSTED_RIGHTS_FACTOR = 0.3
}
