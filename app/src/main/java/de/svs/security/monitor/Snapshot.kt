package de.svs.security.monitor

import de.svs.security.history.LogEvent
import de.svs.security.scan.Identity
import de.svs.security.scan.RiskRules
import org.json.JSONArray
import org.json.JSONObject

data class AppEntry(val label: String, val installer: String?, val lastUpdate: Long, val system: Boolean, val vendor: String? = null)

/** Momentaufnahme der sicherheitsrelevanten Geraetezustaende – wird stuendlich verglichen. */
data class Snapshot(
    val time: Long,
    val apps: Map<String, AppEntry>,
    val accessibility: Set<String>,
    val admins: Set<String>,
    val listeners: Set<String>,
    val home: String?,
    val sms: String?,
    val safeMode: Boolean,
) {
    fun toJson(): String = JSONObject().apply {
        put("time", time)
        put("apps", JSONObject().apply {
            apps.forEach { (k, v) ->
                put(k, JSONObject().put("l", v.label).put("i", v.installer ?: "").put("u", v.lastUpdate).put("s", v.system).put("v", v.vendor ?: ""))
            }
        })
        put("acc", JSONArray(accessibility.toList()))
        put("adm", JSONArray(admins.toList()))
        put("lis", JSONArray(listeners.toList()))
        put("home", home ?: "")
        put("sms", sms ?: "")
        put("safe", safeMode)
    }.toString()

    companion object {
        fun fromJson(s: String): Snapshot {
            val o = JSONObject(s)
            val a = o.getJSONObject("apps")
            val apps = a.keys().asSequence().associateWith { k ->
                val e = a.getJSONObject(k)
                AppEntry(e.getString("l"), e.optString("i").ifEmpty { null }, e.getLong("u"), e.optBoolean("s"), e.optString("v").ifEmpty { null })
            }
            fun set(n: String) = o.optJSONArray(n)?.let { arr -> (0 until arr.length()).map { arr.getString(it) }.toSet() }.orEmpty()
            return Snapshot(
                o.getLong("time"), apps, set("acc"), set("adm"), set("lis"),
                o.optString("home").ifEmpty { null }, o.optString("sms").ifEmpty { null }, o.optBoolean("safe"),
            )
        }

        /** Unterschiede als Chronik-Ereignisse. alert=true -> Warnung per Benachrichtigung. */
        fun diff(old: Snapshot, new: Snapshot, now: Long = new.time): List<LogEvent> {
            val out = mutableListOf<LogEvent>()
            fun lbl(p: String) = new.apps[p]?.label ?: old.apps[p]?.label ?: p
            val systemPkgs = new.apps.filterValues { it.system }.keys
            val vendorPkgs = new.apps.filterValues { it.vendor != null }.keys

            for ((p, e) in new.apps) {
                val before = old.apps[p]
                if (before == null) {
                    val src = Identity.installSource(e.installer, e.system, systemPkgs, vendorPkgs)
                    val unknown = !e.system && e.vendor == null && !src.trusted
                    out += LogEvent(now, "INSTALL", "Neue App: ${e.label}",
                        "Quelle: ${RiskRules.installerLabel(e.installer)}" +
                            if (unknown) " – nicht aus Store, Hersteller oder System" else if (e.vendor != null) " – Herstellerkomponente (${e.vendor}, Signatur bestätigt)" else "",
                        p, alert = unknown)
                }
            }
            for ((p, e) in old.apps) if (p !in new.apps) {
                out += LogEvent(now, "REMOVED", "App entfernt: ${e.label}", "", p, alert = e.system)
            }
            for (p in new.accessibility - old.accessibility) out += LogEvent(now, "ROLE", "Bedienungshilfe eingeschaltet: ${lbl(p)}",
                "Diese App kann jetzt den Bildschirm lesen und das Handy bedienen.", p, alert = true)
            for (p in old.accessibility - new.accessibility) out += LogEvent(now, "ROLE", "Bedienungshilfe ausgeschaltet: ${lbl(p)}", "", p)
            for (p in new.admins - old.admins) out += LogEvent(now, "ROLE", "Neuer Geräteadministrator: ${lbl(p)}",
                "Diese App kann das Handy sperren/löschen und ihre Deinstallation verhindern.", p, alert = true)
            for (p in old.admins - new.admins) out += LogEvent(now, "ROLE", "Geräteadministrator entfernt: ${lbl(p)}", "", p)
            for (p in new.listeners - old.listeners) out += LogEvent(now, "ROLE", "Liest jetzt Benachrichtigungen: ${lbl(p)}", "", p, alert = true)
            if (new.home != old.home && new.home != null) out += LogEvent(now, "ROLE", "Startbildschirm-App gewechselt: ${lbl(new.home)}",
                "Vorher: ${old.home?.let { lbl(it) } ?: "keiner"}. Ein anderer Startbildschirm zeigt andere Widgets.", new.home,
                alert = new.home !in RiskRules.TRUSTED_LAUNCHERS)
            if (new.sms != old.sms && new.sms != null) out += LogEvent(now, "ROLE", "Standard-SMS-App gewechselt: ${lbl(new.sms)}", "", new.sms, alert = true)
            if (new.safeMode && !old.safeMode) out += LogEvent(now, "SAFE_MODE", "Abgesicherter Modus aktiv",
                "Widgets selbst installierter Apps werden dabei vom Startbildschirm entfernt.", alert = true)
            return out
        }
    }
}
