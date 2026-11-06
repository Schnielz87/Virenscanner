package de.svs.security

import de.svs.security.diag.DiagEntry
import de.svs.security.diag.DiagMeta
import de.svs.security.diag.Diagnostics
import de.svs.security.diag.RemovalRisk
import de.svs.security.intel.ThreatDb
import de.svs.security.scan.AppInfo
import de.svs.security.scan.RiskRules
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DiagnosticsTest {
    private val now = 1_800_000_000_000L
    private fun app(pkg: String, label: String, installer: String?, pre: Boolean = false, vendor: String? = null, launcher: Boolean = true,
                    acc: Boolean = false, overlay: Boolean = false, home: Boolean = false) =
        AppInfo(pkg, label, pre, installer, now - 86_400_000L * 40, now, "1", null, emptyList(), emptySet(), launcher, acc, false, false, false, home, overlay,
            preinstalled = pre, vendor = vendor)

    private fun entry(a: AppInfo, inUse: List<String> = emptyList()): DiagEntry {
        val r = RiskRules.assess(a, ThreatDb.EMPTY, now)
        return DiagEntry(r, Diagnostics.removalRisk(r, inUse), inUse)
    }

    @Test fun removalRisks() {
        assertEquals(RemovalRisk.SYSTEM_CRITICAL, entry(app("com.android.systemui", "System UI", null, pre = true, launcher = false)).removal)
        assertEquals(RemovalRisk.SYSTEM_CRITICAL, entry(app("com.android.providers.contacts", "Kontakte-Speicher", null, pre = true, launcher = false)).removal)
        assertEquals(RemovalRisk.SYSTEM, entry(app("com.samsung.android.app.notes", "Samsung Notes", null, pre = true)).removal)
        assertEquals(RemovalRisk.VENDOR_COMPONENT, entry(app("com.samsung.SMT.lang_de_de_l01", "SamsungTTS Deutsch Stimme 1", "com.samsung.SMT", vendor = "Samsung", launcher = false)).removal)
        assertEquals(RemovalRisk.USER_APP, entry(app("com.example.game", "Spiel", "com.android.vending")).removal)
        assertEquals(RemovalRisk.IN_USE, entry(app("com.teslacoilsw.launcher", "Nova", "com.android.vending", home = true), listOf("Startbildschirm")).removal)
    }

    @Test fun jsonExportContainsEverything() {
        val entries = listOf(
            entry(app("com.samsung.SMT.lang_de_de_l01", "SamsungTTS Deutsch Stimme 1", "com.samsung.SMT", vendor = "Samsung", launcher = false)),
            entry(app("com.evil.x", "Player Update", "com.google.android.packageinstaller", launcher = false, acc = true, overlay = true)),
        )
        val json = JSONObject(Diagnostics.toJson(DiagMeta(now, "1.0.15", "samsung SM-X", "Android 15", "2026-10-01", mapOf("domains" to 1), mapOf("Samsung" to 1), true), entries))
        assertEquals("handywaechter-diagnose-1", json.getString("format"))
        val apps = json.getJSONArray("apps")
        assertEquals(2, apps.length())
        val first = apps.getJSONObject(0) // nach Score sortiert
        assertEquals("com.evil.x", first.getString("paket"))
        assertTrue(first.getString("bewertung").startsWith("TREFFER"))
        assertTrue(first.getJSONArray("score_faktoren").length() > 0)
        val tts = apps.getJSONObject(1)
        assertEquals("kein Treffer", tts.getString("bewertung"))
        assertEquals("Herstellerkomponente", tts.getString("entfernen"))
        assertTrue(json.getJSONObject("gewichte").getInt("NO_LAUNCHER_ICON") == 3)
        assertEquals(1, json.getJSONObject("zusammenfassung").getInt("Treffer gesamt"))
    }
}
