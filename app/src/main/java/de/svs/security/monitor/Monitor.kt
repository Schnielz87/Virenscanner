package de.svs.security.monitor

import android.content.Context
import android.provider.Telephony
import de.svs.security.history.EventLog
import de.svs.security.history.LogEvent
import de.svs.security.scan.AppInventory
import java.io.File

/** Erstellt Momentaufnahmen und meldet Veraenderungen. */
object Monitor {

    private fun file(ctx: Context) = File(ctx.filesDir, "snapshot.json")

    fun take(ctx: Context): Snapshot {
        val pm = ctx.packageManager
        val apps = AppInventory.packages(ctx).associate { pi ->
            val ai = pi.applicationInfo
            pi.packageName to AppEntry(
                label = ai?.let { runCatching { pm.getApplicationLabel(it).toString() }.getOrNull() } ?: pi.packageName,
                installer = AppInventory.installerOf(pm, pi.packageName),
                lastUpdate = pi.lastUpdateTime,
                system = AppInventory.isSystem(ai),
            )
        }
        return Snapshot(
            time = System.currentTimeMillis(),
            apps = apps,
            accessibility = AppInventory.accessibilityPackages(ctx),
            admins = AppInventory.deviceAdminPackages(ctx),
            listeners = AppInventory.notificationListenerPackages(ctx),
            home = AppInventory.defaultHome(ctx),
            sms = runCatching { Telephony.Sms.getDefaultSmsPackage(ctx) }.getOrNull(),
            safeMode = pm.isSafeMode,
        )
    }

    /** Vergleicht mit der letzten Aufnahme, protokolliert und warnt. Liefert die neuen Ereignisse. */
    @Synchronized
    fun check(ctx: Context): List<LogEvent> {
        val now = take(ctx)
        val f = file(ctx)
        val old = runCatching { Snapshot.fromJson(f.readText()) }.getOrNull()
        f.writeText(now.toJson())
        if (old == null) {
            EventLog.add(ctx, LogEvent(now.time, "MONITOR", "Überwachung gestartet", "${now.apps.size} Apps erfasst. Ab jetzt wird jede Änderung protokolliert."))
            return emptyList()
        }
        val changes = Snapshot.diff(old, now)
        changes.forEach { EventLog.add(ctx, it) }
        changes.filter { it.alert }.forEach { Notifier.warn(ctx, it.title, it.detail.ifEmpty { "Tippe für Details." }) }
        return changes
    }
}
