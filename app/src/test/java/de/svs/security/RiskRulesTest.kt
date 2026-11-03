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
        val f = RiskRules.evaluate(app(pkg = "com.spy.x"), db, "de.svs.security")
        assertEquals(Severity.CRITICAL, f.single().severity)
    }

    @Test fun knownSpyCert() {
        val f = RiskRules.evaluate(app(certs = listOf("AABB")), db, "x")
        assertEquals(Severity.CRITICAL, f.single().severity)
    }

    @Test fun hiddenSideloadedWithAccessibility() {
        val f = RiskRules.evaluate(app(installer = "com.google.android.packageinstaller", launcher = false, acc = true), db, "x")
        assertTrue(f.any { it.severity == Severity.HIGH && it.title.startsWith("Bedienungshilfe") })
        assertTrue(f.any { it.severity == Severity.HIGH && it.title.startsWith("Versteckte") })
    }

    @Test fun foreignLauncher() {
        val f = RiskRules.evaluate(app(pkg = "com.evil.home", home = true), db, "x")
        assertTrue(f.any { it.title.startsWith("Fremder Startbildschirm") })
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
}
