package de.svs.security

import de.svs.security.intel.ThreatDb
import de.svs.security.scan.AppInfo
import de.svs.security.scan.ComponentKind
import de.svs.security.scan.Identity
import de.svs.security.scan.InstallSource
import de.svs.security.scan.RiskLevel
import de.svs.security.scan.RiskRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mehrstufige Risikoanalyse: False-Positive-Schutz und Erkennung gefaehrlicher Kombinationen. */
class RiskEngineTest {
    private val now = 1_800_000_000_000L
    private val samsung = "AA11SAMSUNG"
    private val google = "BB22GOOGLE"
    private val db = ThreatDb.EMPTY

    /** Vorinstallierte Apps des Geraets -> daraus lernt der Index die Hersteller-Zertifikate. */
    private val index = Identity.VendorIndex(
        mapOf(
            "com.samsung.SMT" to listOf(samsung),
            "com.sec.android.app.launcher" to listOf(samsung),
            "com.google.android.gms" to listOf(google),
            "android" to listOf("PLATFORM"),
        ),
        setOf("PLATFORM"),
    )
    private val systemPkgs = setOf("com.samsung.SMT", "com.sec.android.app.launcher", "com.google.android.gms", "com.sec.android.app.sbrowser",
        "com.samsung.android.packageinstaller")

    private fun app(
        pkg: String, label: String, installer: String?, certs: List<String> = listOf("RANDOMCERT"),
        launcher: Boolean = false, preinstalled: Boolean = false, acc: Boolean = false, admin: Boolean = false,
        overlay: Boolean = false, perms: Set<String> = emptySet(), vendorPkgs: Set<String> = emptySet(), firstInstall: Long = now - 30L * 86_400_000,
    ): AppInfo {
        val vendor = index.verify(pkg, certs)
        return AppInfo(
            pkg, label, preinstalled, installer, firstInstall, firstInstall, "1.0", null, emptyList(), perms, launcher, acc, admin,
            false, false, false, overlay,
            preinstalled = preinstalled, vendor = vendor,
            installSource = Identity.installSource(installer, preinstalled, systemPkgs, vendorPkgs),
            requestedPerms = perms, certSha256 = certs,
        )
    }

    private fun findings(a: AppInfo) = RiskRules.evaluate(a, db, "de.svs.security", now)

    @Test fun samsungTtsWithoutIcon_noAlarm() {
        val a = app("com.samsung.SMT.lang_de_de_l01", "SamsungTTS Deutsch Stimme 1", "com.samsung.SMT", listOf(samsung))
        assertEquals("Samsung", a.vendor)
        val r = RiskRules.assess(a, db, now)
        assertEquals(RiskLevel.NONE, r.level)
        assertEquals(ComponentKind.TTS_VOICE, r.kind)
        assertTrue(r.neutral.any { it.startsWith("Kein App-Symbol: normal für ein(e) TTS-Sprachpaket") })
        assertTrue(r.neutral.any { "Keine kritische Kombination" in it })
        assertTrue(findings(a).isEmpty())
    }

    @Test fun languagePack_noAlarm() {
        val a = app("com.samsung.android.offline.languagemodel.dede", "Samsung Language Pack Deutsch", "com.sec.android.app.samsungapps", listOf(samsung))
        assertEquals(ComponentKind.LANGUAGE_PACK, RiskRules.assess(a, db, now).kind)
        assertTrue(findings(a).isEmpty())
    }

    @Test fun galaxyBudsComponent_noAlarm() {
        // Plugin wird von Galaxy Wearable installiert, das selbst signaturgepruefter Samsung-Code ist
        val wearable = "com.samsung.android.app.watchmanager"
        val a = app("com.samsung.accessory.berrymgr", "Galaxy Buds Live Manager", wearable, listOf(samsung), vendorPkgs = setOf(wearable))
        assertEquals(InstallSource.VENDOR_COMPONENT, a.installSource)
        assertTrue(findings(a).isEmpty())
        // auch ohne bestaetigte Signatur: kein Alarm allein wegen fehlendem Symbol
        val b = app("com.samsung.accessory.berrymgr", "Galaxy Buds Live Manager", wearable, listOf("OTHER"), vendorPkgs = setOf(wearable))
        assertTrue(RiskRules.assess(b, db, now).score < 20)
    }

    @Test fun normalAppWithoutIcon_notAlarmedByThatAlone() {
        val store = app("com.example.helper", "Helper", "com.android.vending")
        assertTrue(findings(store).isEmpty())
        val side = app("com.example.helper", "Helper", "com.google.android.packageinstaller")
        val r = RiskRules.assess(side, db, now)
        assertTrue("Score ${r.score}", r.score < 20)
        assertTrue(r.factors.any { it.startsWith("+3 kein App-Symbol") })
    }

    @Test fun sideloadHiddenAccessibilityOverlay_highRisk() {
        val a = app("com.flashplayer.update", "Player Update", "com.google.android.packageinstaller",
            acc = true, overlay = true, perms = setOf("android.permission.INTERNET"))
        val r = RiskRules.assess(a, db, now)
        assertEquals(RiskLevel.HIGH, r.level)
        assertTrue(r.factors.any { "kein Symbol + unbekannte Quelle + Bedienungshilfe" in it })
        assertTrue(r.factors.any { "Einblenden + Bedienungshilfe" in it })
        val f = findings(a).single()
        assertTrue(f.title.startsWith("Hohes Risiko"))
        assertTrue("keine unbelegte Malware-Aussage", listOf("Virus", "Trojaner", "Malware").none { it in f.title })
    }

    @Test fun unknownSourceDeviceAdmin_highRisk() {
        val a = app("com.lock.screen", "Lock Screen", "com.sec.android.app.sbrowser", launcher = true, admin = true)
        assertEquals(InstallSource.OTHER_APP, a.installSource) // vorinstallierter Browser macht die APK NICHT vertrauenswuerdig
        val r = RiskRules.assess(a, db, now)
        assertTrue("Score ${r.score}", r.score >= 80)
        assertEquals(RiskLevel.HIGH, r.level)
    }

    @Test fun spoofedSamsungPackage_isNotAllowlisted() {
        // Paketname wie Samsung, aber fremde Signatur und als APK installiert
        val a = app("com.samsung.SMT.lang_de_de_l01", "SamsungTTS Deutsch Stimme 1", "com.google.android.packageinstaller", acc = true)
        assertNull(a.vendor)
        val r = RiskRules.assess(a, db, now)
        assertTrue(r.factors.any { "gibt Samsung als Hersteller an" in it })
        assertTrue("Score ${r.score}", r.level >= RiskLevel.SUSPICIOUS)
    }

    @Test fun systemAppNotBlindlyTrusted_butDampened() {
        val a = app("com.sec.android.app.launcher", "One UI Home", null, listOf(samsung), launcher = true, preinstalled = true, acc = true, overlay = true)
        val r = RiskRules.assess(a, db, now)
        assertTrue(r.factors.isNotEmpty()) // Rechte werden weiterhin gezaehlt
        assertTrue("Score ${r.score}", r.score < 20)
    }

    @Test fun installSources() {
        assertEquals(InstallSource.STORE, Identity.installSource("com.android.vending", false, systemPkgs, emptySet()))
        assertEquals(InstallSource.MANUAL_APK, Identity.installSource("com.samsung.android.packageinstaller", false, systemPkgs, emptySet()))
        assertEquals(InstallSource.SYSTEM_COMPONENT, Identity.installSource("com.samsung.SMT", false, systemPkgs, emptySet()))
        assertEquals(InstallSource.UNKNOWN, Identity.installSource(null, false, systemPkgs, emptySet()))
        assertEquals(InstallSource.PREINSTALLED, Identity.installSource(null, true, systemPkgs, emptySet()))
    }

    @Test fun platformSignature() {
        assertEquals("Android", index.verify("com.android.settings", listOf("PLATFORM")))
        assertNull(index.verify("com.google.fake", listOf(samsung))) // Samsung-Zertifikat gilt nicht fuer google-Pakete
        assertEquals("Google", index.verify("com.google.android.tts", listOf(google)))
    }
}
