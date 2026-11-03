package de.svs.security

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import de.svs.security.intel.ThreatIntel
import de.svs.security.monitor.Jobs
import de.svs.security.monitor.Notifier
import de.svs.security.monitor.PackageEventReceiver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class SecurityApp : Application() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    override fun onCreate() {
        super.onCreate()
        Notifier.createChannels(this)
        Jobs.schedule(this)
        scope.launch { ThreatIntel.load(this@SecurityApp) }
        // Installationen in Echtzeit melden, solange die App im Speicher ist
        // (ab Android 8 kommen PACKAGE_ADDED-Meldungen nur an so registrierte Empfaenger).
        val f = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        val r: BroadcastReceiver = PackageEventReceiver()
        ContextCompat.registerReceiver(this, r, f, ContextCompat.RECEIVER_EXPORTED)
    }

    companion object {
        fun of(ctx: Context) = ctx.applicationContext as SecurityApp
    }
}
