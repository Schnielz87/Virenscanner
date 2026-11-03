package de.svs.security.scan

/** [label] fuer Geraete-Befunde, [appLabel] = Risikostufe fuer App-Befunde. */
enum class Severity(val label: String, val appLabel: String, val weight: Int) {
    CRITICAL("Kritisch", "Hohes Risiko", 40),
    HIGH("Hoch", "Verdächtig", 20),
    MEDIUM("Mittel", "Prüfen", 8),
    LOW("Gering", "Geringes Risiko", 2),
    INFO("Hinweis", "Unauffällig", 0),
}

/** Was der Knopf an einem Befund tun soll. */
enum class FixAction { NONE, APP_SETTINGS, UNINSTALL, ACCESSIBILITY, DEVICE_ADMIN, NOTIFICATION_ACCESS, SECURITY_SETTINGS, DEV_SETTINGS, PRIVATE_DNS, HOME_SETTINGS, UPDATE_SETTINGS }

data class Finding(
    val severity: Severity,
    val title: String,
    val detail: String,
    val advice: String,
    val pkg: String? = null,
    val action: FixAction = FixAction.NONE,
    /** Risk Score 0–100 (nur App-Befunde) */
    val score: Int? = null,
    /** Steckbrief: Paket, Identität, Quelle, System/User, Sonderrechte … */
    val facts: List<Pair<String, String>> = emptyList(),
    /** Was den Score erhöht hat ("+25 Bedienungshilfe aktiv") */
    val factors: List<String> = emptyList(),
    /** Warum etwas als unkritisch eingestuft wurde */
    val neutral: List<String> = emptyList(),
) {
    /** Anzeige der Stufe: bei Apps die Risikostufe mit Score */
    val levelText: String get() = if (score != null) "${severity.appLabel} · $score/100" else severity.label
}

/** Alles, was die App ueber eine installierte App weiss. */
data class AppInfo(
    val pkg: String,
    val label: String,
    val system: Boolean,
    val installer: String?,
    val firstInstall: Long,
    val lastUpdate: Long,
    val versionName: String?,
    val sha256: String?,
    val certSha1: List<String>,
    val grantedPerms: Set<String>,
    val hasLauncher: Boolean,
    val accessibility: Boolean,
    val deviceAdmin: Boolean,
    val notificationListener: Boolean,
    val defaultSms: Boolean,
    val defaultHome: Boolean,
    val overlayAllowed: Boolean,
    /** FLAG_SYSTEM: Teil des Geraete-Images (vorinstalliert) */
    val preinstalled: Boolean = system,
    /** vorinstallierte App, die per Update aktualisiert wurde */
    val updatedSystem: Boolean = false,
    /** signaturgepruefter Hersteller ("Samsung", "Google", "Android") oder null */
    val vendor: String? = null,
    val installSource: InstallSource = Identity.installSource(installer, preinstalled, emptySet(), emptySet()),
    val requestedPerms: Set<String> = grantedPerms,
    val certSha256: List<String> = emptyList(),
    val certSubject: String? = null,
    val vpnService: Boolean = false,
    val canInstallPackages: Boolean = false,
)

data class ScanResult(
    val time: Long,
    val appsScanned: Int,
    val apksHashed: Int,
    val findings: List<Finding>,
) {
    /** 0..100, 100 = keine Auffaelligkeiten */
    val score: Int get() = (100 - findings.sumOf { it.severity.weight }).coerceIn(0, 100)
    val worst: Severity? get() = findings.filter { it.severity != Severity.INFO }.minByOrNull { it.severity.ordinal }?.severity
}
