package de.svs.security.monitor

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import de.svs.security.MainActivity
import de.svs.security.R

object Notifier {
    const val CH_WARN = "warnungen"
    const val CH_INFO = "info"
    private var id = (System.currentTimeMillis() % 100000).toInt()

    fun createChannels(ctx: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_WARN, "Sicherheitswarnungen", NotificationManager.IMPORTANCE_HIGH).apply {
            description = "Neue Apps aus unbekannter Quelle, neue Geräteadministratoren, blockierte Betrugsseiten …"
        })
        nm.createNotificationChannel(NotificationChannel(CH_INFO, "Hinweise", NotificationManager.IMPORTANCE_LOW).apply {
            description = "Tägliche Prüfung, Datenaktualisierung, App-Updates"
        })
    }

    fun warn(ctx: Context, title: String, text: String) = post(ctx, CH_WARN, title, text, NotificationCompat.PRIORITY_HIGH)
    fun info(ctx: Context, title: String, text: String) = post(ctx, CH_INFO, title, text, NotificationCompat.PRIORITY_LOW)

    private fun post(ctx: Context, ch: String, title: String, text: String, prio: Int) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val pi = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP).putExtra("tab", "history"),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = NotificationCompat.Builder(ctx, ch)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(prio)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        runCatching { NotificationManagerCompat.from(ctx).notify(id++, n) }
    }
}
