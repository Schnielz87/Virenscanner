package de.svs.security

import de.svs.security.history.LogEvent
import de.svs.security.intel.IocFamily
import de.svs.security.intel.ThreatDb
import de.svs.security.monitor.AppEntry
import de.svs.security.monitor.Snapshot
import de.svs.security.scan.AppInfo
import de.svs.security.scan.RiskRules
import de.svs.security.scan.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskRulesTest {
    private val db = ThreatDb(listOf(IocFamily("SpyX", "stalkerware", setOf("com.spy.x"), setOf("AABB"), setOf("spyx.com"))), emptyList(), emptySet(), emptySet())

    private fun app(pkg: String = "com.example", installer: String? = "com.android.vending", system: Boolean = false, launcher: Boolean = true,
                    acc: Boolean = false, admin: Boolean = false, home: Boolean = false, certs: List<String> = emptyList()) =
        AppInfo(pkg, "Example", system, installer, 0, 0, "1", null, certs, emptySet(), launcher, acc, admin, false, false, home, false)

    @Test fun cleanStoreApp() = assertTrue(RiskRules.evaluate(app(), db, "de.svs.security").isEmpty())

    @Test fun knownSpyPackage() {
        // nur der Paketname stimmt: deutlicher Treffer, aber kein Beweis -> "Verdächtig"
        val f = RiskRules.evaluate(app(pkg = "com.spy.x"), db, "de.svs.security").single()
        assertEquals(Severity.HIGH, f.severity)
        assertTrue(f.title.startsWith("Übereinstimmung mit bekannter Spionage-App"))
    }

    @Test fun knownSpyCert() {
        val f = RiskRules.evaluate(app(certs = listOf("AABB")), db, "x")
        assertEquals(Severity.CRITICAL, f.single().severity)
    }

    @Test fun foreignLauncher() {
        val f = RiskRules.evaluate(app(pkg = "com.evil.home", home = true), db, "x")
        assertTrue(f.single().factors.any { "Startbildschirm" in it })
        assertTrue(RiskRules.evaluate(app(pkg = "com.sec.android.app.launcher", system = true, home = true), db, "x").isEmpty())
    }

    @Test fun snapshotDiff() {
        val base = Snapshot(1, mapOf("a" to AppEntry("A", "com.android.vending", 1, false)), emptySet(), emptySet(), emptySet(), "com.sec.android.app.launcher", null, false)
        val now = base.copy(
            time = 2,
            apps = base.apps + ("evil" to AppEntry("Evil", "com.sec.android.app.sbrowser", 2, false)),
            accessibility = setOf("evil"), home = "evil", safeMode = true,
        )
        val d: List<LogEvent> = Snapshot.diff(base, now)
        assertTrue(d.any { it.type == "INSTALL" && it.alert })
        assertTrue(d.any { it.title.startsWith("Bedienungshilfe eingeschaltet") && it.alert })
        assertTrue(d.any { it.title.startsWith("Startbildschirm-App gewechselt") && it.alert })
        assertTrue(d.any { it.type == "SAFE_MODE" })
        // Hin- und Rueckweg JSON
        assertEquals(now, Snapshot.fromJson(now.toJson()))
    }

    @Test fun snapshotDiff_vendorComponentNoAlarm() {
        val base = Snapshot(1, mapOf("com.samsung.android.app.watchmanager" to AppEntry("Galaxy Wearable", "com.android.vending", 1, false, "Samsung")),
            emptySet(), emptySet(), emptySet(), "com.sec.android.app.launcher", null, false)
        val now = base.copy(time = 2, apps = base.apps + ("com.samsung.accessory.berrymgr" to
            AppEntry("Galaxy Buds Live Manager", "com.samsung.android.app.watchmanager", 2, false, "Samsung")))
        val d = Snapshot.diff(base, now)
        assertTrue(d.single().type == "INSTALL" && !d.single().alert)
    }
}
