package de.svs.security.history

import android.app.AppOpsManager
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import de.svs.security.scan.AppInventory
import de.svs.security.scan.RiskRules

/**
 * Rueckwirkende Chronik: Was ist wann auf dem Handy passiert und durch welche App?
 * Quellen: Android-Nutzungsstatistik (ca. 7–10 Tage rueckwirkend, braucht „Nutzungsdatenzugriff“),
 * Installations-/Updatezeiten aller Apps (unbegrenzt rueckwirkend) und das eigene Protokoll der App.
 */
object Timeline {

    const val LAUNCHER = "com.sec.android.app.launcher"
    val SETTINGS_PKGS = setOf("com.android.settings", "com.samsung.android.settings")
    val INSTALLER_PKGS = setOf("com.google.android.packageinstaller", "com.android.packageinstaller", "com.samsung.android.packageinstaller")
    val BROWSERS = setOf("com.sec.android.app.sbrowser", "com.android.chrome", "org.mozilla.firefox", "com.opera.browser", "com.microsoft.emmx")
    val RESET_RELATED = setOf("com.samsung.android.lool", "com.samsung.android.sm.devicesecurity", "com.sec.android.app.myfiles")

    fun hasUsageAccess(ctx: Context): Boolean {
        val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        else @Suppress("DEPRECATION") ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.packageName)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun build(ctx: Context, from: Long, to: Long): List<LogEvent> {
        val pm = ctx.packageManager
        val labels = HashMap<String, String>()
        fun label(p: String) = labels.getOrPut(p) {
            runCatching { pm.getApplicationLabel(pm.getApplicationInfo(p, 0)).toString() }.getOrDefault(p)
        }
        val out = mutableListOf<LogEvent>()
        out += EventLog.between(ctx, from, to)
        out += installEvents(ctx, pm, from, to, ::label)
        if (hasUsageAccess(ctx)) out += usageEvents(ctx, from, to, ::label)
        return out.sortedByDescending { it.time }
    }

    private fun installEvents(ctx: Context, pm: PackageManager, from: Long, to: Long, label: (String) -> String): List<LogEvent> {
        val out = mutableListOf<LogEvent>()
        for (pi in AppInventory.packages(ctx)) {
            val ai = pi.applicationInfo
            val system = AppInventory.isSystem(ai)
            val installer = AppInventory.installerOf(pm, pi.packageName)
            val unknown = !system && installer !in RiskRules.TRUSTED_INSTALLERS
            if (pi.firstInstallTime in from..to && pi.firstInstallTime > 1_300_000_000_000L) out += LogEvent(
                pi.firstInstallTime, "INSTALL", "App installiert: ${label(pi.packageName)}",
                "Quelle: ${RiskRules.installerLabel(installer)} · Version ${pi.versionName ?: "?"}", pi.packageName, alert = unknown,
            )
            if (pi.lastUpdateTime in from..to && pi.lastUpdateTime - pi.firstInstallTime > 60_000) out += LogEvent(
                pi.lastUpdateTime, "UPDATE", "App aktualisiert: ${label(pi.packageName)}",
                "Version ${pi.versionName ?: "?"} · Quelle: ${RiskRules.installerLabel(installer)}", pi.packageName, alert = unknown,
            )
        }
        return out
    }

    private fun usageEvents(ctx: Context, from: Long, to: Long, label: (String) -> String): List<LogEvent> {
        val usm = ctx.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
        val events = runCatching { usm.queryEvents(from, to) }.getOrNull() ?: return emptyList()
        val out = mutableListOf<LogEvent>()
        val e = UsageEvents.Event()
        // Aufeinanderfolgende Aktivitaeten derselben App zu einer Sitzung zusammenfassen
        var curPkg: String? = null
        var curStart = 0L
        var curEnd = 0L
        fun closeSession() {
            val p = curPkg ?: return
            out += sessionEvent(p, curStart, curEnd, label(p))
            curPkg = null
        }
        while (events.hasNextEvent()) {
            events.getNextEvent(e)
            val p = e.packageName ?: continue
            val t = e.timeStamp
            when (e.eventType) {
                UsageEvents.Event.ACTIVITY_RESUMED -> {
                    if (p != curPkg) { closeSession(); curPkg = p; curStart = t }
                    curEnd = t
                }
                UsageEvents.Event.ACTIVITY_PAUSED, 23 /* ACTIVITY_STOPPED */ -> if (p == curPkg) curEnd = t
                UsageEvents.Event.SCREEN_NON_INTERACTIVE -> closeSession()
                UsageEvents.Event.KEYGUARD_HIDDEN -> out += LogEvent(t, "UNLOCK", "Handy entsperrt", "Mit PIN/Muster/Biometrie oder ohne Sperre")
                26 /* DEVICE_SHUTDOWN */ -> { closeSession(); out += LogEvent(t, "SHUTDOWN", "Handy ausgeschaltet / Neustart", alert = true) }
                27 /* DEVICE_STARTUP */ -> out += LogEvent(t, "BOOT", "Handy gestartet", alert = true)
            }
        }
        closeSession()
        return out
    }

    private fun sessionEvent(p: String, start: Long, end: Long, label: String): LogEvent {
        val dur = ((end - start) / 1000).coerceAtLeast(0)
        val d = if (dur >= 60) "${dur / 60} min ${dur % 60} s" else "$dur s"
        return when {
            p in INSTALLER_PKGS -> LogEvent(start, "USAGE", "App-Installation gestartet ($label)", "Dauer $d – hier wurde eine APK-Datei geöffnet bzw. installiert", p, alert = true)
            p in SETTINGS_PKGS -> LogEvent(start, "USAGE", "Einstellungen geöffnet", "Dauer $d – z. B. Apps/Speicher/Daten löschen", p, alert = dur > 5)
            p == LAUNCHER -> LogEvent(start, "HOME", "Startbildschirm ($label)", "Dauer $d", p)
            p in BROWSERS -> LogEvent(start, "USAGE", "Browser: $label", "Dauer $d", p)
            p in RESET_RELATED -> LogEvent(start, "USAGE", label, "Dauer $d", p, alert = true)
            else -> LogEvent(start, "USAGE", label, "Dauer $d", p)
        }
    }
}
