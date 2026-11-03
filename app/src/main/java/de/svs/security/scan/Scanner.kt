package de.svs.security.scan

import android.app.KeyguardManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import de.svs.security.intel.ThreatIntel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.TimeUnit

object Scanner {

    suspend fun run(ctx: Context, onProgress: (String, Float) -> Unit = { _, _ -> }): ScanResult = withContext(Dispatchers.Default) {
        onProgress("Lese installierte Apps …", 0f)
        val apps = AppInventory.collect(ctx, hashUserApps = true) { done, total ->
            onProgress("Prüfe App $done von $total …", done.toFloat() / total.coerceAtLeast(1) * 0.9f)
        }
        val db = ThreatIntel.db
        val findings = mutableListOf<Finding>()
        apps.forEach { findings += RiskRules.evaluate(it, db, ctx.packageName) }
        onProgress("Prüfe Geräteeinstellungen …", 0.95f)
        findings += deviceChecks(ctx)
        val result = ScanResult(
            time = System.currentTimeMillis(),
            appsScanned = apps.size,
            apksHashed = apps.count { it.sha256 != null },
            findings = findings.sortedBy { it.severity.ordinal },
        )
        save(ctx, result)
        onProgress("Fertig", 1f)
        result
    }

    fun deviceChecks(ctx: Context): List<Finding> {
        val out = mutableListOf<Finding>()
        val cr = ctx.contentResolver

        if (ctx.packageManager.isSafeMode) out += Finding(
            Severity.HIGH, "Handy läuft im abgesicherten Modus",
            "Im abgesicherten Modus sind alle selbst installierten Apps deaktiviert und ihre Widgets werden vom Startbildschirm entfernt.",
            "Handy normal neu starten (Ein/Aus → Neu starten). Entfernte Widgets müssen danach neu hinzugefügt werden.",
        )

        val km = ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!km.isDeviceSecure) out += Finding(
            Severity.HIGH, "Keine Bildschirmsperre",
            "Das Handy ist nicht mit PIN, Muster, Passwort oder Fingerabdruck gesichert. Jeder, der es in die Hand nimmt, kann Apps und Widgets ändern.",
            "Einstellungen → Sperrbildschirm → Sperrbildschirmtyp: PIN oder Passwort einrichten.", action = FixAction.SECURITY_SETTINGS,
        )

        val adb = runCatching { Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1 }.getOrDefault(false)
        if (adb) out += Finding(
            Severity.MEDIUM, "USB-Debugging ist eingeschaltet",
            "Über USB-Debugging kann ein angeschlossener Computer Apps installieren und das Handy steuern.",
            "Entwickleroptionen → USB-Debugging ausschalten (sofern du es nicht selbst brauchst).", action = FixAction.DEV_SETTINGS,
        )

        // Sicherheitspatch-Alter
        runCatching {
            val patch = SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(Build.VERSION.SECURITY_PATCH)
            if (patch != null) {
                val days = TimeUnit.MILLISECONDS.toDays(System.currentTimeMillis() - patch.time)
                if (days > 120) out += Finding(
                    if (days > 365) Severity.HIGH else Severity.MEDIUM,
                    "Sicherheitsupdate ist ${days / 30} Monate alt",
                    "Letzter Android-Sicherheitspatch: ${Build.VERSION.SECURITY_PATCH}. Bekannte Lücken sind damit eventuell offen.",
                    "Einstellungen → Software-Update → Herunterladen und installieren.", action = FixAction.UPDATE_SETTINGS,
                )
            }
        }

        // Root-Hinweise
        val su = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk", "/data/local/xbin/su", "/data/local/bin/su")
        if (su.any { File(it).exists() } || Build.TAGS?.contains("test-keys") == true) out += Finding(
            Severity.HIGH, "Gerät ist gerootet oder verändert",
            "Es wurden Root-Spuren gefunden. Schadsoftware mit Root-Rechten kann sich tief im System verstecken.",
            "Wenn du das Handy nicht selbst gerootet hast: Daten sichern und auf Werkseinstellungen zurücksetzen.",
        )

        // Privates DNS / VPN
        runCatching {
            val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val net = cm.activeNetwork
            val caps = net?.let { cm.getNetworkCapabilities(it) }
            val vpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            val lp = net?.let { cm.getLinkProperties(it) }
            val privateDns = Build.VERSION.SDK_INT >= 28 && lp?.isPrivateDnsActive == true && lp.privateDnsServerName != null
            if (!vpn && !privateDns) out += Finding(
                Severity.LOW, "Kein Schutzfilter für Webseiten aktiv",
                "Weder der Web-Schutz dieser App noch ein filterndes „Privates DNS“ ist eingeschaltet. Betrugsseiten wie die Sperr-Meldung von gestern werden so nicht blockiert.",
                "Im Tab „Schutz“ den Web-Schutz einschalten oder Privates DNS „dns.quad9.net“ einstellen.", action = FixAction.PRIVATE_DNS,
            )
        }

        // Unbekannte Quellen: welche Apps duerfen APKs installieren?
        val installers = runCatching {
            val pm = ctx.packageManager
            AppInventory.packages(ctx).filter { pi ->
                val ai = pi.applicationInfo ?: return@filter false
                !AppInventory.isSystem(ai) && pi.packageName != ctx.packageName &&
                    pi.requestedPermissions.orEmpty().contains("android.permission.REQUEST_INSTALL_PACKAGES") &&
                    AppInventory.opAllowed(ctx, ai, "android:request_install_packages")
            }.map { runCatching { pm.getApplicationLabel(it.applicationInfo!!).toString() }.getOrDefault(it.packageName) }
        }.getOrDefault(emptyList())
        if (installers.isNotEmpty()) out += Finding(
            Severity.LOW, "Apps dürfen andere Apps installieren",
            "Folgende Apps dürfen „unbekannte Apps installieren“: ${installers.joinToString(", ")}. Besonders bei Browsern ist das ein häufiger Weg für Schad-Apps.",
            "Einstellungen → Apps → ⋮ → Spezieller Zugriff → Unbekannte Apps installieren: nur erlauben, wenn nötig.",
            action = FixAction.APP_SETTINGS,
        )
        return out
    }

    // ---- letztes Ergebnis speichern ----

    private fun file(ctx: Context) = File(ctx.filesDir, "last_scan.json")

    fun save(ctx: Context, r: ScanResult) {
        val o = JSONObject().put("time", r.time).put("apps", r.appsScanned).put("hashed", r.apksHashed)
            .put("findings", JSONArray().apply {
                r.findings.forEach {
                    put(JSONObject().put("sev", it.severity.name).put("title", it.title).put("detail", it.detail)
                        .put("advice", it.advice).put("pkg", it.pkg ?: "").put("action", it.action.name)
                        .put("score", it.score ?: -1)
                        .put("facts", JSONArray(it.facts.map { (k, v) -> JSONArray(listOf(k, v)) }))
                        .put("factors", JSONArray(it.factors)).put("neutral", JSONArray(it.neutral)))
                }
            })
        file(ctx).writeText(o.toString())
    }

    private fun strings(a: JSONArray?) = a?.let { (0 until it.length()).map { i -> it.getString(i) } }.orEmpty()

    fun last(ctx: Context): ScanResult? = runCatching {
        val o = JSONObject(file(ctx).readText())
        val arr = o.getJSONArray("findings")
        ScanResult(o.getLong("time"), o.getInt("apps"), o.optInt("hashed"), (0 until arr.length()).map { i ->
            val f = arr.getJSONObject(i)
            Finding(
                Severity.valueOf(f.getString("sev")), f.getString("title"), f.getString("detail"), f.getString("advice"),
                f.getString("pkg").ifEmpty { null }, runCatching { FixAction.valueOf(f.getString("action")) }.getOrDefault(FixAction.NONE),
                score = f.optInt("score", -1).takeIf { it >= 0 },
                facts = f.optJSONArray("facts")?.let { a -> (0 until a.length()).map { a.getJSONArray(it).let { p -> p.getString(0) to p.getString(1) } } }.orEmpty(),
                factors = strings(f.optJSONArray("factors")),
                neutral = strings(f.optJSONArray("neutral")),
            )
        })
    }.getOrNull()
}
