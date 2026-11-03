package de.svs.security.scan

import de.svs.security.intel.ThreatDb
import java.util.concurrent.TimeUnit

/** Risikostufe aus dem Score (Grenzen in [RiskConfig]). */
enum class RiskLevel(val label: String) {
    NONE("Unauffällig"), LOW("Geringes Risiko"), CHECK("Prüfen"), SUSPICIOUS("Verdächtig"), HIGH("Hohes Risiko");

    val severity: Severity get() = when (this) {
        HIGH -> Severity.CRITICAL; SUSPICIOUS -> Severity.HIGH; CHECK -> Severity.MEDIUM; LOW -> Severity.LOW; NONE -> Severity.INFO
    }

    companion object {
        fun of(score: Int) = when {
            score >= RiskConfig.LEVEL_HIGH -> HIGH
            score >= RiskConfig.LEVEL_SUSPICIOUS -> SUSPICIOUS
            score >= RiskConfig.LEVEL_CHECK -> CHECK
            score >= RiskConfig.LEVEL_LOW -> LOW
            else -> NONE
        }
    }
}

/** Ergebnis der Bewertung einer App – mit allen Gruenden. */
data class AppAssessment(
    val app: AppInfo,
    val score: Int,
    val level: RiskLevel,
    /** Faktoren, die den Score erhoeht haben ("+25 Bedienungshilfe aktiv") */
    val factors: List<String>,
    /** Warum etwas als unkritisch eingestuft wurde */
    val neutral: List<String>,
    /** Kurzbeschreibung der Identitaet, z. B. "System-/Herstellerkomponente (Samsung, Signatur bestätigt)" */
    val identity: String,
    val kind: ComponentKind,
    val rights: List<String>,
    val iocMatch: String?,
)

/**
 * Mehrstufige Risikoanalyse je App: Identitaet -> Sonderrechte -> Kombinationen -> Score.
 * Einzige Bewertungslogik der App (Scanner, Sofortpruefung, Bericht nutzen sie).
 */
object RiskRules {

    val TRUSTED_INSTALLERS = Identity.STORES

    /** Bekannte, unbedenkliche Startbildschirme (Launcher). */
    val TRUSTED_LAUNCHERS = setOf(
        "com.sec.android.app.launcher", "com.sec.android.emergencylauncher", "com.google.android.apps.nexuslauncher",
        "com.android.launcher3", "com.google.android.launcher", "com.miui.home", "com.huawei.android.launcher",
        "com.oneplus.launcher", "com.motorola.launcher3", "com.microsoft.launcher", "com.teslacoilsw.launcher",
    )

    private val SMS_PERMS = setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS")
    private val PHONE_PERMS = setOf("android.permission.READ_CALL_LOG", "android.permission.CALL_PHONE", "android.permission.READ_PHONE_NUMBERS", "android.permission.PROCESS_OUTGOING_CALLS")
    private const val CONTACTS = "android.permission.READ_CONTACTS"
    private const val MIC = "android.permission.RECORD_AUDIO"
    private const val CAMERA = "android.permission.CAMERA"
    private const val FINE_LOC = "android.permission.ACCESS_FINE_LOCATION"
    private const val BG_LOC = "android.permission.ACCESS_BACKGROUND_LOCATION"
    private const val BOOT = "android.permission.RECEIVE_BOOT_COMPLETED"
    private const val INTERNET = "android.permission.INTERNET"

    /** Ist die Herkunft unbekannt (weder Store, noch Hersteller, noch System)? */
    fun isSideloaded(a: AppInfo) = !a.system && a.vendor == null && !a.installSource.trusted

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
        "com.samsung.android.app.watchmanager" -> "über Galaxy Wearable installiert"
        "com.samsung.SMT" -> "über Samsung TTS installiert"
        "de.svs.security" -> "SVS Security (Update)"
        else -> "über $installer installiert"
    }

    private fun pts(p: Int, factor: Double) = Math.round(p * factor).toInt()

    fun assess(a: AppInfo, db: ThreatDb, now: Long = System.currentTimeMillis()): AppAssessment {
        val factors = mutableListOf<String>()
        val neutral = mutableListOf<String>()
        var score = 0
        fun add(p: Int, why: String) { if (p > 0) { score += p; factors += "+$p $why" } }

        val kind = Identity.kind(a.pkg, a.label)
        val verified = a.vendor != null
        val trustedIdentity = verified || a.preinstalled
        val unknown = isSideloaded(a)
        val rightsFactor = if (trustedIdentity) RiskConfig.TRUSTED_RIGHTS_FACTOR else 1.0

        val identity = when {
            verified && a.preinstalled -> "System-/Herstellerkomponente (${a.vendor}, vorinstalliert, Signatur bestätigt)"
            verified -> "Herstellerkomponente (${a.vendor}, Signatur bestätigt)"
            a.preinstalled -> "Vorinstallierte Systemkomponente"
            a.installSource == InstallSource.STORE -> "App aus offiziellem Store"
            a.installSource.trusted -> "Nutzer-App, ${a.installSource.label}"
            else -> "Nutzer-App, ${a.installSource.label}"
        }

        // 1) Indikator-Treffer
        var ioc: String? = null
        a.sha256?.let { h -> db.hashThreat(h)?.let { ioc = it; add(RiskConfig.IOC_HASH, "APK-Fingerabdruck stimmt mit der bekannten Spionage-App „$it“ überein") } }
        a.certSha1.firstNotNullOfOrNull { db.certThreat(it) }?.let { if (ioc == null) { ioc = it; add(RiskConfig.IOC_CERT, "Signatur-Zertifikat gehört zur bekannten Spionage-App „$it“") } }
        if (ioc == null && !trustedIdentity) db.packageThreat(a.pkg)?.let { ioc = it; add(RiskConfig.IOC_PACKAGE, "Paketname steht auf der Liste bekannter Spionage-Apps („$it“)") }

        // 2) Herkunft & Identitaet
        if (unknown) {
            add(RiskConfig.UNKNOWN_SOURCE, "nicht aus Store/Hersteller/System (${a.installSource.label}: ${installerLabel(a.installer)})")
            if (a.installSource == InstallSource.OTHER_APP && a.installer in Identity.RELAY_INSTALLERS) add(RiskConfig.VIA_BROWSER_OR_MESSENGER, "über Browser/Messenger/Dateimanager erhalten")
        } else {
            neutral += "Herkunft: ${if (a.preinstalled) "vorinstalliert" else a.installSource.label}"
        }
        if (verified) neutral += "Signatur von ${a.vendor} bestätigt (gleiches Zertifikat wie vorinstallierte ${a.vendor}-Apps)"

        if (!a.hasLauncher) {
            when {
                trustedIdentity || kind != ComponentKind.APP && !unknown ->
                    neutral += "Kein App-Symbol: normal für ${if (kind == ComponentKind.APP) "Systemkomponenten" else "ein(e) ${kind.label}"}"
                else -> add(RiskConfig.NO_LAUNCHER_ICON, "kein App-Symbol (allein unkritisch)")
            }
        }
        val odd = if (trustedIdentity) null else Identity.unusualName(a.pkg, a.label)
        odd?.let { add(RiskConfig.UNUSUAL_NAME, it) }
        val imp = Identity.impersonation(a.pkg, a.label, verified, a.preinstalled)
            ?.takeIf { Identity.claimedVendor(a.pkg) != null || unknown }
        imp?.let { add(RiskConfig.IMPERSONATION, it) }

        // 3) Sonderrechte (einzeln)
        val rights = mutableListOf<String>()
        val g = a.grantedPerms
        fun right(cond: Boolean, p: Int, name: String) { if (cond) { rights += name; add(pts(p, rightsFactor), name + if (rightsFactor < 1) " (reduziert gewichtet: bestätigte Identität)" else "") } }
        right(a.accessibility, RiskConfig.ACCESSIBILITY, "Bedienungshilfe aktiv")
        right(a.deviceAdmin, RiskConfig.DEVICE_ADMIN, "Geräteadministrator")
        right(a.overlayAllowed, RiskConfig.OVERLAY, "darf über anderen Apps einblenden")
        right(a.notificationListener, RiskConfig.NOTIFICATION_LISTENER, "liest Benachrichtigungen")
        right(a.canInstallPackages, RiskConfig.INSTALL_PACKAGES, "darf Apps installieren")
        right(a.vpnService && !trustedIdentity, RiskConfig.VPN_SERVICE, "bringt einen VPN-Dienst mit")
        right(a.defaultSms && !a.preinstalled, RiskConfig.DEFAULT_SMS, "ist Standard-SMS-App")
        right(a.defaultHome && a.pkg !in TRUSTED_LAUNCHERS, RiskConfig.FOREIGN_LAUNCHER, "ist als Startbildschirm eingestellt")
        right(g.any { it in SMS_PERMS }, RiskConfig.SMS, "SMS lesen/senden")
        right(g.any { it in PHONE_PERMS }, RiskConfig.PHONE, "Telefon/Anrufliste")
        right(CONTACTS in g, RiskConfig.CONTACTS, "Kontakte")
        right(MIC in g, RiskConfig.MICROPHONE, "Mikrofon")
        right(CAMERA in g, RiskConfig.CAMERA, "Kamera")
        right(BG_LOC in g, RiskConfig.BACKGROUND_LOCATION, "Standort im Hintergrund")
        right(FINE_LOC in g && BG_LOC !in g, RiskConfig.LOCATION, "genauer Standort")
        if (BOOT in a.requestedPerms && unknown) { rights += "Autostart nach dem Einschalten"; add(RiskConfig.AUTOSTART, "startet automatisch nach dem Einschalten") }

        // 4) Kombinationen
        val powerful = a.accessibility || a.deviceAdmin || a.overlayAllowed || a.notificationListener
        if (!a.hasLauncher && unknown && a.accessibility) add(RiskConfig.COMBO_HIDDEN_ACCESSIBILITY, "Kombination: kein Symbol + unbekannte Quelle + Bedienungshilfe")
        if (a.overlayAllowed && a.accessibility) add(pts(RiskConfig.COMBO_OVERLAY_ACCESSIBILITY, rightsFactor), "Kombination: Einblenden + Bedienungshilfe")
        if (unknown && a.deviceAdmin) add(RiskConfig.COMBO_UNKNOWN_ADMIN, "Kombination: unbekannte Quelle + Geräteadministrator")
        val recent = a.firstInstall > 0 && now - a.firstInstall <= TimeUnit.DAYS.toMillis(RiskConfig.RECENT_DAYS.toLong())
        if (recent && unknown && (odd != null || imp != null) && powerful) add(RiskConfig.COMBO_RECENT_ODD_POWERFUL, "Kombination: kürzlich installiert + ungewöhnlicher Name + Sonderrechte")
        if (unknown && INTERNET in a.requestedPerms && (a.accessibility || a.overlayAllowed)) add(RiskConfig.COMBO_WEB_POWERFUL, "Kombination: kann Webseiten laden/öffnen + Bedienungshilfe/Einblenden")
        val spy = listOf(MIC in g, CAMERA in g, CONTACTS in g, g.any { it in PHONE_PERMS }, FINE_LOC in g || BG_LOC in g).count { it }
        if (unknown && spy >= 3) add(RiskConfig.COMBO_SPY_PERMS, "Kombination: unbekannte Quelle + $spy Überwachungs-Rechte")

        if (!powerful && !unknown && ioc == null) neutral += "Keine kritische Kombination von Sonderrechten erkannt"
        else if (!powerful && ioc == null) neutral += "Keine Bedienungshilfe, kein Geräteadministrator, kein Einblenden, kein Benachrichtigungszugriff"

        val s = score.coerceIn(0, 100)
        return AppAssessment(a, s, RiskLevel.of(s), factors, neutral, identity, kind, rights, ioc)
    }

    /** Treffer fuer die Befundliste (ab [RiskConfig.SHOW_FROM]). */
    fun evaluate(a: AppInfo, db: ThreatDb, ownPkg: String, now: Long = System.currentTimeMillis()): List<Finding> {
        if (a.pkg == ownPkg) return emptyList()
        val r = assess(a, db, now)
        if (r.score < RiskConfig.SHOW_FROM) return emptyList()
        return listOf(toFinding(r))
    }

    fun toFinding(r: AppAssessment): Finding {
        val a = r.app
        val title = when {
            r.iocMatch != null -> "Übereinstimmung mit bekannter Spionage-App „${r.iocMatch}“: ${a.label}"
            r.level == RiskLevel.HIGH -> "Hohes Risiko: ${a.label}"
            r.level == RiskLevel.SUSPICIOUS -> "Verdächtige App: ${a.label}"
            r.level == RiskLevel.CHECK -> "Manuelle Prüfung empfohlen: ${a.label}"
            else -> "Geringes Risiko: ${a.label}"
        }
        val detail = "Auffällig wegen: " + r.factors.joinToString("; ") { it.substringAfter(' ') }
        val advice = when {
            r.iocMatch != null || r.level == RiskLevel.HIGH ->
                "Wenn du die App nicht bewusst installiert hast: Sonderrechte (Bedienungshilfe/Geräteadministrator) entziehen und deinstallieren. Danach wichtige Passwörter von einem anderen Gerät ändern."
            r.level == RiskLevel.SUSPICIOUS -> "Prüfen, ob du die App kennst und die Sonderrechte brauchst. Wenn nicht: Rechte entziehen und deinstallieren."
            r.level == RiskLevel.CHECK -> "Prüfen, ob die Sonderrechte gewollt sind."
            else -> "Meist harmlos, z. B. selbst installierte APK – nur zur Kenntnis."
        }
        val action = when {
            r.level >= RiskLevel.SUSPICIOUS && a.deviceAdmin -> FixAction.DEVICE_ADMIN
            r.level >= RiskLevel.SUSPICIOUS && a.accessibility -> FixAction.ACCESSIBILITY
            r.level >= RiskLevel.SUSPICIOUS -> FixAction.UNINSTALL
            a.defaultHome && a.pkg !in TRUSTED_LAUNCHERS -> FixAction.HOME_SETTINGS
            else -> FixAction.APP_SETTINGS
        }
        return Finding(
            r.level.severity, title, detail, advice, a.pkg, action,
            score = r.score,
            facts = listOf(
                "Risikostufe" to "${r.level.label} (Score ${r.score}/100)",
                "Paket" to a.pkg,
                "Identität" to r.identity,
                "Art" to r.kind.label,
                "System/User" to if (a.preinstalled) "System-App (vorinstalliert${if (a.updatedSystem) ", aktualisiert" else ""})" else "User-App (nachträglich installiert)",
                "Installationsquelle" to "${r.app.installSource.label} – ${installerLabel(a.installer)}",
                "Sonderrechte" to r.rights.ifEmpty { listOf("keine") }.joinToString(", "),
            ) + (a.certSubject?.let { listOf("Signiert von" to it) } ?: emptyList()),
            factors = r.factors,
            neutral = r.neutral,
        )
    }
}
