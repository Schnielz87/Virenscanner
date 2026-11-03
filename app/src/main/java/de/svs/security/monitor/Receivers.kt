package de.svs.security.monitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import de.svs.security.vpn.WebShieldService
import de.svs.security.history.EventLog
import de.svs.security.history.LogEvent
import de.svs.security.history.Timeline

/**
 * Android meldet „App-Daten gelöscht“ und „App vollständig entfernt“ auch an schlafende Apps.
 * Genau diese Ereignisse erklaeren z. B. verschwundene Widgets (Daten des Startbildschirms geloescht).
 */
class PackageEventReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val pkg = intent.data?.schemeSpecificPart ?: return
        if (pkg == ctx.packageName) return
        val label = runCatching { ctx.packageManager.getApplicationLabel(ctx.packageManager.getApplicationInfo(pkg, 0)).toString() }.getOrDefault(pkg)
        val now = System.currentTimeMillis()
        when (intent.action) {
            Intent.ACTION_PACKAGE_DATA_CLEARED -> {
                val launcher = pkg == Timeline.LAUNCHER || pkg == de.svs.security.scan.AppInventory.defaultHome(ctx)
                val e = LogEvent(now, "DATA_CLEARED", "App-Daten gelöscht: $label",
                    if (launcher) "Die Daten des Startbildschirms wurden gelöscht – dadurch verschwinden alle Widgets und die Symbol-Anordnung."
                    else "Alle gespeicherten Daten dieser App wurden zurückgesetzt (Einstellungen → Apps → Speicher → Daten löschen).",
                    pkg, alert = true)
                EventLog.add(ctx, e)
                Notifier.warn(ctx, e.title, e.detail)
            }
            Intent.ACTION_PACKAGE_FULLY_REMOVED -> {
                EventLog.add(ctx, LogEvent(now, "REMOVED", "App deinstalliert: $pkg", "", pkg))
                Jobs.monitorNow(ctx)
            }
            Intent.ACTION_PACKAGE_ADDED, Intent.ACTION_PACKAGE_REPLACED -> {
                if (intent.action == Intent.ACTION_PACKAGE_ADDED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                Jobs.checkPackage(ctx, pkg)
            }
        }
    }
}

/** Neustarts protokollieren (inkl. abgesichertem Modus) und Ueberwachung sicherstellen. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, "android.intent.action.QUICKBOOT_POWERON" -> {
                val safe = ctx.packageManager.isSafeMode
                EventLog.add(ctx, LogEvent(System.currentTimeMillis(), if (safe) "SAFE_MODE" else "BOOT",
                    if (safe) "Neustart im abgesicherten Modus" else "Handy neu gestartet",
                    if (safe) "Im abgesicherten Modus entfernt Android die Widgets aller selbst installierten Apps vom Startbildschirm." else "",
                    alert = safe))
                if (safe) Notifier.warn(ctx, "Abgesicherter Modus aktiv", "Widgets selbst installierter Apps werden entfernt. Handy normal neu starten.")
                Jobs.schedule(ctx)
                Jobs.monitorNow(ctx)
                // Web-Schutz wieder einschalten, falls er vor dem Neustart an war
                if (WebShieldService.wanted(ctx) && VpnService.prepare(ctx) == null) {
                    runCatching { ctx.startService(Intent(ctx, WebShieldService::class.java)) }
                }
            }
            Intent.ACTION_MY_PACKAGE_REPLACED -> Jobs.schedule(ctx)
        }
    }
}
