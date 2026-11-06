package de.svs.security.diag

import de.svs.security.scan.AppAssessment
import de.svs.security.scan.ComponentKind
import de.svs.security.scan.RiskConfig
import de.svs.security.scan.RiskLevel
import org.json.JSONArray
import org.json.JSONObject

/** Was passiert, wenn man die App entfernt/deaktiviert? */
enum class RemovalRisk(val label: String, val advice: String) {
    SYSTEM_CRITICAL("Systemkritisch", "NICHT deaktivieren – Handy kann instabil werden oder Grundfunktionen (Telefon, Startbildschirm, Einstellungen, Updates) fallen aus."),
    IN_USE("Aktuell in Benutzung", "Wird gerade als Startbildschirm, Tastatur, SMS-App oder Bedienungshilfe verwendet – vorher eine Alternative einstellen."),
    SYSTEM("Systemkomponente", "Lässt sich nur deaktivieren, nicht löschen. Meist unkritisch, aber die zugehörige Funktion fällt weg – nur wenn nötig."),
    VENDOR_COMPONENT("Herstellerkomponente", "Entfernen schadet dem System nicht, aber die Funktion (z. B. Stimme, Sprachpaket, Buds-Steuerung) fällt weg."),
    USER_APP("Nutzer-App", "Kann gefahrlos deinstalliert werden."),
}

/** Ein Diagnose-Eintrag je installierter App. */
data class DiagEntry(val a: AppAssessment, val removal: RemovalRisk, val inUse: List<String>)

data class DiagMeta(
    val created: Long,
    val appVersion: String,
    val device: String,
    val android: String,
    val securityPatch: String,
    val intel: Map<String, Any>,
    val vendorCertCounts: Map<String, Int>,
    val usageAccess: Boolean,
)

object Diagnostics {

    /** Pakete, ohne die Android bzw. ein Samsung-Handy nicht sauber laeuft. */
    private val CRITICAL = setOf(
        "android", "com.android.systemui", "com.android.phone", "com.android.settings", "com.android.shell",
        "com.android.server.telecom", "com.android.bluetooth", "com.android.nfc", "com.android.location.fused",
        "com.android.permissioncontroller", "com.google.android.permissioncontroller",
        "com.android.packageinstaller", "com.google.android.packageinstaller", "com.samsung.android.packageinstaller",
        "com.android.vending", "com.google.android.gms", "com.google.android.gsf", "com.google.android.webview", "com.android.webview",
        "com.sec.android.app.launcher", "com.samsung.android.honeyboard", "com.sec.imsservice", "com.samsung.android.biometrics.app.setting",
        "com.android.networkstack", "com.google.android.networkstack", "com.android.mtp", "com.android.externalstorage",
        "com.samsung.android.providers.context", "com.android.keychain", "com.android.se", "com.android.wifi.resources",
    )
    private val CRITICAL_PREFIXES = listOf("com.android.providers.", "android.", "com.android.networkstack", "com.google.android.networkstack",
        "com.android.inputmethod", "com.samsung.android.dqagent", "com.samsung.ims", "com.sec.phone", "com.samsung.android.network")

    fun removalRisk(a: AppAssessment, inUse: List<String>): RemovalRisk {
        val p = a.app.pkg
        return when {
            a.app.preinstalled && (p in CRITICAL || CRITICAL_PREFIXES.any { p.startsWith(it) } ||
                (a.kind == ComponentKind.SERVICE && !a.app.hasLauncher)) -> RemovalRisk.SYSTEM_CRITICAL
            inUse.isNotEmpty() -> RemovalRisk.IN_USE
            a.app.preinstalled -> RemovalRisk.SYSTEM
            a.app.vendor != null -> RemovalRisk.VENDOR_COMPONENT
            else -> RemovalRisk.USER_APP
        }
    }

    /** Einschaetzung fuer die Auswertung: wie ist der Treffer zu lesen? */
    fun verdict(e: DiagEntry): String = when {
        e.a.iocMatch != null -> "INDIKATOR-TREFFER (bekannte Spionage-App)"
        e.a.score >= RiskConfig.SHOW_FROM -> "TREFFER (${e.a.level.label})"
        else -> "kein Treffer"
    }

    fun summary(entries: List<DiagEntry>): Map<String, Int> = linkedMapOf(
        "Apps gesamt" to entries.size,
        "Treffer gesamt" to entries.count { it.a.score >= RiskConfig.SHOW_FROM },
        "  davon Hohes Risiko" to entries.count { it.a.level == RiskLevel.HIGH },
        "  davon Verdächtig" to entries.count { it.a.level == RiskLevel.SUSPICIOUS },
        "  davon Prüfen" to entries.count { it.a.level == RiskLevel.CHECK },
        "  davon Geringes Risiko" to entries.count { it.a.level == RiskLevel.LOW },
        "Indikator-Treffer" to entries.count { it.a.iocMatch != null },
        "Vorinstalliert" to entries.count { it.a.app.preinstalled },
        "Herstellerkomponenten (Signatur bestätigt)" to entries.count { it.a.app.vendor != null },
        "Unbekannte Quelle" to entries.count { it.a.factors.any { f -> "nicht aus Store/Hersteller/System" in f } },
        "Ohne App-Symbol" to entries.count { !it.a.app.hasLauncher },
        "Systemkritisch (nicht entfernen)" to entries.count { it.removal == RemovalRisk.SYSTEM_CRITICAL },
    )

    /** Maschinenlesbarer Export (JSON) – fuer die Auswertung. */
    fun toJson(meta: DiagMeta, entries: List<DiagEntry>): String {
        val root = JSONObject()
        root.put("format", "handywaechter-diagnose-1")
        root.put("erstellt", meta.created)
        root.put("app_version", meta.appVersion)
        root.put("geraet", meta.device)
        root.put("android", meta.android)
        root.put("sicherheitspatch", meta.securityPatch)
        root.put("nutzungsdaten_zugriff", meta.usageAccess)
        root.put("bedrohungsdaten", JSONObject(meta.intel))
        root.put("hersteller_zertifikate", JSONObject(meta.vendorCertCounts as Map<*, *>))
        root.put("gewichte", JSONObject().apply {
            RiskConfig::class.java.declaredFields.filter { java.lang.reflect.Modifier.isStatic(it.modifiers) && it.name != "INSTANCE" }
                .forEach { f -> runCatching { f.isAccessible = true; put(f.name, f.get(null)) } }
        })
        root.put("zusammenfassung", JSONObject(summary(entries).mapKeys { it.key.trim() } as Map<*, *>))
        root.put("apps", JSONArray().apply {
            entries.sortedWith(compareByDescending<DiagEntry> { it.a.score }.thenBy { it.a.app.label.lowercase() }).forEach { e -> put(entryJson(e)) }
        })
        return root.toString(1)
    }

    private fun entryJson(e: DiagEntry): JSONObject {
        val a = e.a; val app = a.app
        return JSONObject()
            .put("label", app.label)
            .put("paket", app.pkg)
            .put("bewertung", verdict(e))
            .put("score", a.score)
            .put("stufe", a.level.label)
            .put("identitaet", a.identity)
            .put("art", a.kind.label)
            .put("vorinstalliert", app.preinstalled)
            .put("system_aktualisiert", app.updatedSystem)
            .put("hersteller_bestaetigt", app.vendor ?: JSONObject.NULL)
            .put("quelle", app.installSource.name)
            .put("installer", app.installer ?: JSONObject.NULL)
            .put("app_symbol", app.hasLauncher)
            .put("version", app.versionName ?: JSONObject.NULL)
            .put("installiert", app.firstInstall)
            .put("aktualisiert", app.lastUpdate)
            .put("zertifikat_aussteller", app.certSubject ?: JSONObject.NULL)
            .put("zertifikat_sha256", JSONArray(app.certSha256.map { it.take(16) }))
            .put("apk_sha256", app.sha256 ?: JSONObject.NULL)
            .put("sonderrechte", JSONArray(a.rights))
            .put("rechte_erteilt", JSONArray(app.grantedPerms.map { it.removePrefix("android.permission.") }.sorted()))
            .put("score_faktoren", JSONArray(a.factors))
            .put("unkritisch_weil", JSONArray(a.neutral))
            .put("indikator", a.iocMatch ?: JSONObject.NULL)
            .put("in_benutzung", JSONArray(e.inUse))
            .put("entfernen", e.removal.label)
            .put("entfernen_hinweis", e.removal.advice)
    }
}
