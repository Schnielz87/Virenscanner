package de.svs.security.monitor

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import de.svs.security.history.EventLog
import de.svs.security.history.LogEvent
import de.svs.security.intel.ThreatIntel
import de.svs.security.scan.AppInventory
import de.svs.security.scan.RiskRules
import de.svs.security.scan.Scanner
import de.svs.security.scan.Severity
import de.svs.security.update.UpdateChecker
import java.util.concurrent.TimeUnit

object Jobs {
    fun schedule(ctx: Context) {
        val wm = WorkManager.getInstance(ctx)
        wm.enqueueUniquePeriodicWork(
            "daily", ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<DailyWorker>(24, TimeUnit.HOURS)
                .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build(),
        )
        wm.enqueueUniquePeriodicWork(
            "monitor", ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<MonitorWorker>(1, TimeUnit.HOURS).build(),
        )
    }

    fun monitorNow(ctx: Context) = WorkManager.getInstance(ctx)
        .enqueueUniqueWork("monitor-now", ExistingWorkPolicy.REPLACE, OneTimeWorkRequestBuilder<MonitorWorker>().build())

    fun checkPackage(ctx: Context, pkg: String) = WorkManager.getInstance(ctx).enqueue(
        OneTimeWorkRequestBuilder<PackageCheckWorker>().setInputData(workDataOf("pkg" to pkg)).build(),
    )
}

/** Stuendlich: hat sich an Apps, Rechten, Startbildschirm etwas geaendert? */
class MonitorWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result {
        runCatching { Monitor.check(applicationContext) }
        return Result.success()
    }
}

/** Taeglich: Bedrohungsdaten laden, Vollpruefung, Update-Pruefung. */
class DailyWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result {
        val ctx = applicationContext
        val ok = runCatching { ThreatIntel.update(ctx) }.getOrDefault(0)
        if (ThreatIntel.db.domainCount == 0) ThreatIntel.load(ctx)
        val before = Scanner.last(ctx)?.findings?.map { it.title }?.toSet().orEmpty()
        val r = runCatching { Scanner.run(ctx) }.getOrNull()
        if (r != null) {
            val fresh = r.findings.filter { it.severity <= Severity.HIGH && it.title !in before }
            EventLog.add(ctx, LogEvent(r.time, "SCAN", "Tägliche Prüfung: ${r.findings.count { it.severity <= Severity.MEDIUM }} Auffälligkeiten",
                "${r.appsScanned} Apps geprüft, Bedrohungsdaten: $ok von ${ThreatIntel.SOURCES.size} Quellen aktualisiert", alert = fresh.isNotEmpty()))
            fresh.forEach { Notifier.warn(ctx, it.title, it.detail) }
        }
        runCatching {
            val rel = UpdateChecker.latest()
            if (rel.build > UpdateChecker.currentBuild(ctx)) Notifier.info(ctx, "Neue Version von SVS Security", "${rel.title} – in der App unter „Mehr → Update“ installieren.")
        }
        return Result.success()
    }
}

/** Sofortpruefung einer neu installierten/aktualisierten App. */
class PackageCheckWorker(ctx: Context, p: WorkerParameters) : CoroutineWorker(ctx, p) {
    override suspend fun doWork(): Result {
        val ctx = applicationContext
        val pkg = inputData.getString("pkg") ?: return Result.success()
        if (ThreatIntel.db.domainCount == 0) ThreatIntel.load(ctx)
        val app = AppInventory.collect(ctx, hashUserApps = false).firstOrNull { it.pkg == pkg } ?: return Result.success()
        val hashed = app.copy(sha256 = ctx.packageManager.getApplicationInfo(pkg, 0).sourceDir?.let { AppInventory.sha256(java.io.File(it)) })
        RiskRules.evaluate(hashed, ThreatIntel.db, ctx.packageName).filter { it.severity <= Severity.MEDIUM }.forEach {
            EventLog.add(ctx, LogEvent(System.currentTimeMillis(), "THREAT", it.title, it.detail, pkg, alert = true))
            Notifier.warn(ctx, it.title, it.detail)
        }
        Monitor.check(ctx)
        return Result.success()
    }
}
