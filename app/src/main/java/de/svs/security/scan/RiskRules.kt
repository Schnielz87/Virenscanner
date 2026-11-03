package de.svs.security.scan

import de.svs.security.intel.ThreatDb

/**
 * Bewertungsregeln je App. Reine Logik (Unit-Tests in RiskRulesTest).
 */
object RiskRules {

    /** Offizielle App-Stores. Alles andere gilt als "aus unbekannter Quelle" (Sideloading). */
    val TRUSTED_INSTALLERS = setOf(
        "com.android.vending",                 // Google Play
        "com.sec.android.app.samsungapps",     // Galaxy Store
        "com.google.android.feedback",
        "com.amazon.venezia",
        "com.huawei.appmarket",
    )

    /** Bekannte, unbedenkliche Startbildschirme (Launcher). */
    val TRUSTED_LAUNCHERS = setOf(
        "com.sec.android.app.launcher",        // Samsung One UI Home
        "com.sec.android.emergencylauncher",
        "com.google.android.apps.nexuslauncher",
        "com.android.launcher3",
        "com.google.android.launcher",
        "com.miui.home", "com.huawei.android.launcher", "com.oneplus.launcher", "com.motorola.launcher3",
        "com.microsoft.launcher", "com.teslacoilsw.launcher",
    )

    private val SMS_PERMS = setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS")
    private val SPY_PERMS = setOf(
        "android.permission.RECORD_AUDIO", "android.permission.READ_CALL_LOG", "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.CAMERA",
    )

    fun isSideloaded(a: AppInfo) = !a.system && a.installer !in TRUSTED_INSTALLERS

    fun installerLabel(installer: String?): String = when (installer) {
        null, "" -> "unbekannt / vorinstalliert"
        "com.android.vending" -> "Google Play Store"
        "com.sec.android.app.samsungapps" -> "Samsung Galaxy Store"
        "com.google.android.packageinstaller", "com.android.packageinstaller", "com.samsung.android.packageinstaller" ->
            "manuell installiert (APK-Datei)"
        "com.sec.android.app.sbrowser" -> "über Samsung Internet heruntergeladen"
        "com.android.chrome" -> "über Chrome heruntergeladen"
        "com.sec.android.app.myfiles" -> "über „Eigene Dateien“ installiert"
        "com.whatsapp" -> "über WhatsApp erhalten"
        "org.telegram.messenger" -> "über Telegram erhalten"
        "de.svs.security" -> "SVS Security (Update)"
        else -> installer
    }

    fun evaluate(a: AppInfo, db: ThreatDb, ownPkg: String): List<Finding> {
        if (a.pkg == ownPkg) return emptyList()
        val out = mutableListOf<Finding>()
        val name = "${a.label} (${a.pkg})"
        val side = isSideloaded(a)

        // 1) Bekannte Schadsoftware laut Bedrohungsdaten
        a.sha256?.let { h -> db.hashThreat(h)?.let { out += critical(a, "Bekannte Schad-App erkannt: $it", "Der Fingerabdruck (SHA-256) von $name stimmt mit einer bekannten Spionage-/Schad-App überein.") } }
        if (!a.system) db.packageThreat(a.pkg)?.let { out += critical(a, "Spionage-App erkannt: $it", "Der Paketname von $name gehört zu einer bekannten Spionage-App ($it).") }
        a.certSha1.firstNotNullOfOrNull { db.certThreat(it) }?.let {
            out += critical(a, "Signatur einer Spionage-App: $it", "$name ist mit dem Zertifikat einer bekannten Spionage-App ($it) signiert.")
        }
        if (out.isNotEmpty()) return out

        if (a.system) {
            // Systemapps nur pruefen, wenn sie ungewoehnliche Rollen haben
            if (a.defaultHome && a.pkg !in TRUSTED_LAUNCHERS) out += launcherFinding(a, name)
            return out
        }

        // 2) Gefaehrliche Rollen / Rechte
        if (a.accessibility) out += Finding(
            if (side) Severity.HIGH else Severity.MEDIUM,
            "Bedienungshilfe aktiv: ${a.label}",
            "$name darf als Bedienungshilfe den Bildschirm mitlesen und Eingaben auslösen. Das ist der häufigste Weg, über den Banking-Trojaner Handys fernsteuern." +
                if (side) " Die App stammt NICHT aus einem offiziellen Store." else "",
            "Wenn du diese App nicht bewusst als Bedienungshilfe eingerichtet hast: Bedienungshilfe ausschalten und App deinstallieren.",
            a.pkg, FixAction.ACCESSIBILITY,
        )
        if (a.deviceAdmin) out += Finding(
            if (side) Severity.HIGH else Severity.LOW,
            "Geräteadministrator: ${a.label}",
            "$name ist als Geräteadministrator eingetragen und kann z. B. das Handy sperren, löschen oder die eigene Deinstallation verhindern.",
            "Unter Einstellungen → Sicherheit → Geräteadministratoren entfernen, falls unbekannt – danach lässt sich die App deinstallieren.",
            a.pkg, FixAction.DEVICE_ADMIN,
        )
        if (a.notificationListener && side) out += Finding(
            Severity.MEDIUM, "Liest Benachrichtigungen mit: ${a.label}",
            "$name hat Zugriff auf alle Benachrichtigungen (z. B. SMS-TANs, Chat-Nachrichten) und stammt nicht aus einem offiziellen Store.",
            "Zugriff auf Benachrichtigungen entziehen, falls nicht gewollt.", a.pkg, FixAction.NOTIFICATION_ACCESS,
        )
        if (a.defaultHome && a.pkg !in TRUSTED_LAUNCHERS) out += launcherFinding(a, name)
        if (a.defaultSms) out += Finding(
            if (side) Severity.HIGH else Severity.LOW, "Fremde Standard-SMS-App: ${a.label}",
            "$name ist als Standard-SMS-App eingestellt und kann alle SMS (auch Bank-TANs) lesen und senden.",
            "Unter Einstellungen → Apps → Standard-Apps wieder „Nachrichten“ wählen, falls nicht gewollt.", a.pkg, FixAction.APP_SETTINGS,
        )

        // 3) Herkunft und Verhalten
        if (side) {
            val sms = a.grantedPerms.any { it in SMS_PERMS }
            val spy = a.grantedPerms.count { it in SPY_PERMS }
            when {
                !a.hasLauncher -> out += Finding(
                    Severity.HIGH, "Versteckte App ohne Symbol: ${a.label}",
                    "$name wurde außerhalb eines App-Stores installiert (${installerLabel(a.installer)}) und hat kein App-Symbol – typisch für Trojaner, die sich verstecken.",
                    "Prüfen, ob du die App kennst. Wenn nicht: deinstallieren.", a.pkg, FixAction.UNINSTALL,
                )
                sms || spy >= 3 -> out += Finding(
                    Severity.MEDIUM, "Unbekannte Quelle mit weitreichenden Rechten: ${a.label}",
                    "$name stammt nicht aus einem offiziellen Store (${installerLabel(a.installer)}) und darf ${if (sms) "SMS lesen" else "Mikrofon/Standort/Kontakte nutzen"}.",
                    "Nur behalten, wenn du die App bewusst installiert hast.", a.pkg, FixAction.APP_SETTINGS,
                )
                else -> out += Finding(
                    Severity.LOW, "Aus unbekannter Quelle installiert: ${a.label}",
                    "$name wurde ${installerLabel(a.installer)}.",
                    "Unbedenklich, wenn du die APK selbst installiert hast (z. B. eigene Apps von GitHub).", a.pkg, FixAction.APP_SETTINGS,
                )
            }
            if (a.overlayAllowed) out += Finding(
                Severity.MEDIUM, "Darf über anderen Apps einblenden: ${a.label}",
                "$name (unbekannte Quelle) darf Fenster über anderen Apps anzeigen – so werden z. B. gefälschte Anmeldemasken über Banking-Apps gelegt.",
                "Unter App-Info → „Über anderen Apps einblenden“ ausschalten, falls nicht nötig.", a.pkg, FixAction.APP_SETTINGS,
            )
        }
        return out
    }

    private fun launcherFinding(a: AppInfo, name: String) = Finding(
        Severity.HIGH, "Fremder Startbildschirm aktiv: ${a.label}",
        "$name ist als Startbildschirm (Launcher) eingestellt. Ein anderer Launcher zeigt andere Widgets und Symbole an – das kann verschwundene Widgets erklären.",
        "Einstellungen → Apps → Standard-Apps → Startbildschirm → „One UI Home“ wählen.", a.pkg, FixAction.HOME_SETTINGS,
    )

    private fun critical(a: AppInfo, title: String, detail: String) = Finding(
        Severity.CRITICAL, title, detail,
        "Sofort deinstallieren. Falls das nicht geht: zuerst unter Geräteadministratoren/Bedienungshilfen die Rechte entziehen. Danach Passwörter (Google, Bank, E-Mail) von einem anderen Gerät aus ändern.",
        a.pkg, FixAction.UNINSTALL,
    )
}
