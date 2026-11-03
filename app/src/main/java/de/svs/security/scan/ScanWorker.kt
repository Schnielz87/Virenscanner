package de.svs.security.scan

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import de.svs.security.MainActivity
import de.svs.security.R
import de.svs.security.intel.ThreatIntel
import de.svs.security.monitor.Notifier
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * Vollpruefung als Hintergrundauftrag mit Fortschritts-Benachrichtigung (Vordergrunddienst).
 * Laeuft weiter, wenn die App minimiert oder geschlossen wird.
 */
class ScanWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {

    override suspend fun getForegroundInfo(): ForegroundInfo = foreground("Prüfung wird gestartet …", 0f)

    override suspend fun doWork(): Result = coroutineScope {
        val ctx = applicationContext
        runCatching { setForeground(foreground("Prüfung läuft …", 0f)) }
        if (ThreatIntel.db.domainCount == 0) ThreatIntel.load(ctx)

        val state = MutableStateFlow("Starte …" to 0f)
        // Fortschritt hoechstens zweimal pro Sekunde weitergeben (App-Anzeige + Benachrichtigung)
        val reporter = launch {
            var last: Pair<String, Float>? = null
            while (true) {
                val s = state.value
                if (s != last) {
                    last = s
                    setProgress(workDataOf(KEY_TEXT to s.first, KEY_P to s.second))
                    runCatching { setForeground(foreground(s.first, s.second)) }
                }
                delay(500)
            }
        }
        val result = runCatching { Scanner.run(ctx) { t, p -> state.value = t to p } }
        reporter.cancel()
        result.fold(
            onSuccess = { r ->
                val hits = r.findings.count { it.severity <= Severity.MEDIUM }
                Notifier.info(ctx, "Prüfung abgeschlossen",
                    if (hits == 0) "${r.appsScanned} Apps geprüft – keine verdächtigen Apps gefunden."
                    else "${r.appsScanned} Apps geprüft – $hits Treffer zum Ansehen.")
                Result.success()
            },
            onFailure = { Result.failure(workDataOf(KEY_TEXT to (it.message ?: "Fehler"))) },
        )
    }

    private fun foreground(text: String, p: Float): ForegroundInfo {
        val ctx = applicationContext
        val open = PendingIntent.getActivity(ctx, 2, Intent(ctx, MainActivity::class.java).putExtra("tab", "scan")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP), PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(ctx, Notifier.CH_INFO)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Handywächter prüft dein Handy")
            .setContentText(text)
            .setProgress(100, (p * 100).toInt(), p <= 0f)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .build()
        return if (Build.VERSION.SDK_INT >= 29) ForegroundInfo(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        else ForegroundInfo(NOTIF_ID, n)
    }

    companion object {
        const val NAME = "scan-now"
        const val KEY_TEXT = "text"
        const val KEY_P = "p"
        private const val NOTIF_ID = 4711

        fun start(ctx: Context) = WorkManager.getInstance(ctx).enqueueUniqueWork(
            NAME, ExistingWorkPolicy.KEEP,
            OneTimeWorkRequestBuilder<ScanWorker>().setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST).build(),
        )
    }
}
