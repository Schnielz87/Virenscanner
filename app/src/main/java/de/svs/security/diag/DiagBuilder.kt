package de.svs.security.diag

import android.content.Context
import android.os.Build
import android.provider.Settings
import de.svs.security.history.Timeline
import de.svs.security.intel.ThreatIntel
import de.svs.security.scan.AppInventory
import de.svs.security.scan.RiskRules
import de.svs.security.update.UpdateChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Wertet ALLE installierten Apps mit der normalen Risikobewertung aus (nichts wird ausgelassen). */
object DiagBuilder {

    class Result(val meta: DiagMeta, val entries: List<DiagEntry>)

    suspend fun build(ctx: Context, onProgress: (String) -> Unit = {}): Result = withContext(Dispatchers.Default) {
        val now = System.currentTimeMillis()
        if (ThreatIntel.db.domainCount == 0) ThreatIntel.load(ctx)
        onProgress("Lese alle Apps …")
        val apps = AppInventory.collect(ctx, hashUserApps = false) { d, t -> onProgress("Lese App $d von $t …") }
            .filter { it.pkg != ctx.packageName }
        onProgress("Prüfe Fingerabdrücke von Apps aus unbekannter Quelle …")
        val pm = ctx.packageManager
        val withHash = apps.map { a ->
            if (RiskRules.isSideloaded(a)) a.copy(sha256 = runCatching { pm.getApplicationInfo(a.pkg, 0).sourceDir?.let { AppInventory.sha256(File(it)) } }.getOrNull())
            else a
        }
        val ime = runCatching { Settings.Secure.getString(ctx.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)?.substringBefore('/') }.getOrNull()
        onProgress("Bewerte ${withHash.size} Apps …")
        val entries = withHash.map { app ->
            val a = RiskRules.assess(app, ThreatIntel.db, now)
            val inUse = buildList {
                if (app.defaultHome) add("Startbildschirm")
                if (app.defaultSms) add("SMS-App")
                if (app.pkg == ime) add("Tastatur")
                if (app.accessibility) add("Bedienungshilfe")
                if (app.deviceAdmin) add("Geräteadministrator")
            }
            DiagEntry(a, Diagnostics.removalRisk(a, inUse), inUse)
        }
        val st = ThreatIntel.status.value
        val meta = DiagMeta(
            created = now,
            appVersion = UpdateChecker.currentVersion(ctx),
            device = "${Build.MANUFACTURER} ${Build.MODEL}",
            android = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})",
            securityPatch = Build.VERSION.SECURITY_PATCH ?: "?",
            intel = mapOf("stand" to st.lastUpdate, "pakete" to st.packages, "zertifikate" to st.certificates, "hashes" to st.hashes, "domains" to st.domains),
            vendorCertCounts = withHash.mapNotNull { it.vendor }.groupingBy { it }.eachCount(),
            usageAccess = Timeline.hasUsageAccess(ctx),
        )
        Result(meta, entries)
    }
}
