package de.svs.security.report

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import de.svs.security.history.Timeline
import de.svs.security.intel.ThreatIntel
import de.svs.security.scan.AppInventory
import de.svs.security.scan.RiskRules
import de.svs.security.scan.Scanner
import de.svs.security.update.UpdateChecker
import de.svs.security.vpn.WebShieldService
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Sammelt alle Daten auf dem Handy und erzeugt die Gesamtuebersicht. */
object ReportBuilder {
    const val EVENT_DAYS = 7

    suspend fun build(ctx: Context): String = withContext(Dispatchers.Default) {
        val now = System.currentTimeMillis()
        if (ThreatIntel.db.domainCount == 0) ThreatIntel.load(ctx)
        val apps = AppInventory.collect(ctx, hashUserApps = false).filter { it.pkg != ctx.packageName }
        // Fingerabdruck nur fuer Apps aus unbekannter Quelle (schnell genug)
        val withHash = apps.map { a ->
            if (RiskRules.isSideloaded(a)) a.copy(sha256 = runCatching {
                ctx.packageManager.getApplicationInfo(a.pkg, 0).sourceDir?.let { AppInventory.sha256(java.io.File(it)) }
            }.getOrNull()) else a
        }
        val cleared = withHash.filter { !it.hasLauncher && !it.preinstalled }
            .map { RiskRules.assess(it, ThreatIntel.db, now) }
            .filter { it.score < de.svs.security.scan.RiskConfig.SHOW_FROM }
            .sortedBy { it.app.label.lowercase() }
            .map { a -> "${a.app.label} (${a.app.pkg}) – Score ${a.score} – ${a.identity} – ${a.neutral.firstOrNull { n -> n.startsWith("Kein App-Symbol") } ?: "kein App-Symbol, keine kritischen Sonderrechte"}" }
        val events = runCatching { Timeline.build(ctx, now - EVENT_DAYS * 86_400_000L, now) }.getOrDefault(emptyList())
        val st = ThreatIntel.status.value
        ReportFormatter.format(
            ReportData(
                created = now,
                device = "${Build.MANUFACTURER} ${Build.MODEL}",
                android = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
                securityPatch = Build.VERSION.SECURITY_PATCH ?: "?",
                appVersion = UpdateChecker.currentVersion(ctx),
                scan = Scanner.last(ctx),
                deviceStatus = deviceStatus(ctx),
                apps = withHash,
                events = events,
                eventDays = EVENT_DAYS,
                cleared = cleared,
                intel = listOf(
                    "Zuletzt aktualisiert" to fmt(st.lastUpdate),
                    "Spionage-App-Familien" to "${st.families}",
                    "Bekannte Paketnamen" to "${st.packages}",
                    "Signatur-Zertifikate" to "${st.certificates}",
                    "APK-Fingerabdrücke" to "${st.hashes}",
                    "Gefährliche Webseiten" to "${st.domains}",
                ),
            ),
        )
    }

    private fun fmt(t: Long) = if (t <= 0) "nie (mitgelieferter Grundstock)" else SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.GERMANY).format(Date(t))
    private fun yn(b: Boolean) = if (b) "ja" else "nein"

    private fun deviceStatus(ctx: Context): List<Pair<String, String>> {
        val cr = ctx.contentResolver
        val km = ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val lp = runCatching { cm.getLinkProperties(cm.activeNetwork) }.getOrNull()
        val vpn = runCatching { cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }.getOrDefault(false)
        val privateDns = if (Build.VERSION.SDK_INT >= 28 && lp?.isPrivateDnsActive == true) lp.privateDnsServerName ?: "automatisch" else "aus"
        val notif = Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        return listOf(
            "Abgesicherter Modus aktiv" to yn(ctx.packageManager.isSafeMode),
            "Bildschirmsperre (PIN/Muster/…)" to yn(km.isDeviceSecure),
            "USB-Debugging" to yn(runCatching { Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1 }.getOrDefault(false)),
            "Entwickleroptionen" to yn(runCatching { Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1 }.getOrDefault(false)),
            "Startbildschirm-App" to (AppInventory.defaultHome(ctx) ?: "?"),
            "Web-Schutz (SVS)" to if (WebShieldService.isEnabled(ctx)) "an (${WebShieldService.blockedCount(ctx)} blockiert)" else "aus",
            "VPN aktiv" to yn(vpn),
            "Privates DNS" to privateDns,
            "Nutzungsdatenzugriff (Verlauf)" to if (Timeline.hasUsageAccess(ctx)) "erlaubt" else "NICHT erlaubt – Verlauf unvollständig",
            "Benachrichtigungen erlaubt" to yn(notif),
        )
    }
}
