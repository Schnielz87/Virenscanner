package de.svs.security.scan

enum class Severity(val label: String, val weight: Int) {
    CRITICAL("Kritisch", 40),
    HIGH("Hoch", 20),
    MEDIUM("Mittel", 8),
    LOW("Gering", 2),
    INFO("Hinweis", 0),
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
)

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
