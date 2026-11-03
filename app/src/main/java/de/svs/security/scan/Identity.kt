package de.svs.security.scan

/**
 * Herkunft und Identitaet einer App – reine Logik (Unit-Tests in RiskEngineTest).
 *
 * Grundsatz: Ein Paketname wie com.samsung.* beweist nichts, er laesst sich nachahmen.
 * Als Herstellerkomponente gilt eine App nur, wenn ihr Signatur-Zertifikat mit dem einer
 * VORINSTALLIERTEN App desselben Herstellers uebereinstimmt (oder sie mit dem Plattform-Schluessel
 * signiert ist). Diesen Schluessel besitzt nur der Hersteller.
 */

/** Woher eine App kommt. */
enum class InstallSource(val label: String, val trusted: Boolean) {
    PREINSTALLED("vorinstalliert (Teil des Systems)", true),
    STORE("offizieller App-Store", true),
    VENDOR_COMPONENT("über eine signaturgeprüfte Herstellerkomponente installiert", true),
    SYSTEM_COMPONENT("über eine vorinstallierte Systemkomponente installiert", true),
    MANUAL_APK("manuell als APK-Datei installiert", false),
    OTHER_APP("über eine andere App installiert", false),
    UNKNOWN("Quelle unbekannt (z. B. per Computer/ADB)", false),
}

/** Art der Komponente – erklaert, warum z. B. ein fehlendes App-Symbol normal ist. */
enum class ComponentKind(val label: String) {
    TTS_VOICE("TTS-Sprachpaket / Stimme"),
    LANGUAGE_PACK("Sprachpaket"),
    ACCESSORY("Geräte-Zubehör-/Companion-Modul"),
    PLUGIN("Plugin / Erweiterung"),
    KEYBOARD("Tastatur / Eingabemethode"),
    OVERLAY_THEME("Design-/Overlay-Paket"),
    SERVICE("Hintergrunddienst / Systembibliothek"),
    WIDGET("Widget-Paket"),
    APP("App"),
}

object Identity {

    /** App-Stores. */
    val STORES = setOf(
        "com.android.vending", "com.sec.android.app.samsungapps", "com.google.android.feedback",
        "com.amazon.venezia", "com.huawei.appmarket",
    )

    /**
     * „Weiterreicher“: Apps, ueber die ein Nutzer eine APK-Datei oeffnet. Auch wenn sie vorinstalliert sind,
     * macht das die installierte App NICHT vertrauenswuerdig.
     */
    val PACKAGE_INSTALLERS = setOf("com.google.android.packageinstaller", "com.android.packageinstaller", "com.samsung.android.packageinstaller")
    val RELAY_INSTALLERS = PACKAGE_INSTALLERS + setOf(
        "com.sec.android.app.sbrowser", "com.android.chrome", "org.mozilla.firefox", "com.opera.browser", "com.microsoft.emmx",
        "com.sec.android.app.myfiles", "com.google.android.apps.nbu.files", "com.android.documentsui",
        "com.whatsapp", "org.telegram.messenger", "com.google.android.gm", "com.samsung.android.email.provider",
        "com.google.android.apps.docs", "com.android.shell",
    )

    private val VENDOR_PREFIXES = listOf(
        "com.samsung." to "Samsung", "com.sec." to "Samsung", "com.samsung" to "Samsung", "com.osp." to "Samsung", "com.knox." to "Samsung",
        "com.google." to "Google", "com.android." to "Android", "android" to "Android",
    )

    /** Hersteller, den der Paketname BEHAUPTET (nicht bewiesen). */
    fun claimedVendor(pkg: String): String? =
        VENDOR_PREFIXES.firstOrNull { (p, _) -> pkg == p || pkg.startsWith(p) }?.second

    /**
     * Index der Hersteller-Zertifikate, gebildet aus den vorinstallierten Apps des Geraets.
     * [preinstalled]: Paketname -> SHA-256 der Signatur-Zertifikate.
     */
    class VendorIndex(preinstalled: Map<String, List<String>>, private val platformCerts: Set<String>) {
        private val certs: Map<String, Set<String>> = preinstalled.entries
            .mapNotNull { (p, c) -> claimedVendor(p)?.let { it to c } }
            .groupBy({ it.first }, { it.second }).mapValues { (_, l) -> l.flatten().toSet() }

        /** Bestaetigter Hersteller oder null. */
        fun verify(pkg: String, appCerts: List<String>): String? {
            if (appCerts.isEmpty()) return null
            if (appCerts.any { it in platformCerts }) return claimedVendor(pkg) ?: "Android-Plattform"
            val v = claimedVendor(pkg) ?: return null
            val known = certs[v].orEmpty() + if (v == "Android") certs["Google"].orEmpty() else emptySet()
            return v.takeIf { appCerts.any { it in known } }
        }

        fun isPlatform(appCerts: List<String>) = appCerts.any { it in platformCerts }

        companion object { val EMPTY = VendorIndex(emptyMap(), emptySet()) }
    }

    fun installSource(installer: String?, preinstalled: Boolean, systemPkgs: Set<String>, verifiedVendorPkgs: Set<String>): InstallSource = when {
        installer.isNullOrBlank() -> if (preinstalled) InstallSource.PREINSTALLED else InstallSource.UNKNOWN
        installer in STORES -> InstallSource.STORE
        installer in PACKAGE_INSTALLERS -> InstallSource.MANUAL_APK
        installer in RELAY_INSTALLERS -> InstallSource.OTHER_APP
        installer in verifiedVendorPkgs -> InstallSource.VENDOR_COMPONENT
        installer in systemPkgs -> InstallSource.SYSTEM_COMPONENT
        preinstalled -> InstallSource.PREINSTALLED
        else -> InstallSource.OTHER_APP
    }

    fun kind(pkg: String, label: String): ComponentKind {
        val p = pkg.lowercase(); val l = label.lowercase()
        return when {
            ".smt." in p || p.endsWith(".smt") || "tts" in p || "tts" in l || "stimme" in l || "voice" in l -> ComponentKind.TTS_VOICE
            "languagepack" in p || "language" in p || "langpack" in p || ".lang_" in p || "sprachpaket" in l || "language" in l -> ComponentKind.LANGUAGE_PACK
            "accessory" in p || "buds" in p || "buds" in l || "watchmanager" in p || "wearable" in p || "gear" in p || "watch" in l -> ComponentKind.ACCESSORY
            "plugin" in p || "plugin" in l || "extension" in p -> ComponentKind.PLUGIN
            "inputmethod" in p || "honeyboard" in p || "keyboard" in p || "tastatur" in l -> ComponentKind.KEYBOARD
            "overlay" in p || ".theme" in p || "themes" in p || ".rro" in p -> ComponentKind.OVERLAY_THEME
            "widget" in p || "widget" in l -> ComponentKind.WIDGET
            p.endsWith("provider") || p.endsWith("service") || "framework" in p || p.endsWith("agent") || ".res" in p || "library" in p -> ComponentKind.SERVICE
            else -> ComponentKind.APP
        }
    }

    /** Ungewoehnlicher Paketname (Grund) oder null. */
    fun unusualName(pkg: String, label: String): String? {
        val parts = pkg.split('.')
        if (parts.size < 2) return "Paketname ohne Punkt-Struktur"
        if (parts.all { it.length <= 2 }) return "Paketname besteht nur aus Kürzeln"
        val random = parts.drop(1).firstOrNull { s -> s.length >= 8 && s.count { it in "aeiouy" } * 6 < s.length }
        if (random != null) return "Paketname wirkt zufällig erzeugt („$random“)"
        if (label.isBlank() || label == pkg) return "App hat keinen lesbaren Namen"
        return null
    }

    private val IMPERSONATION_WORDS = listOf("system", "android", "google", "samsung", "update", "service", "security", "settings", "einstellungen", "sicherheit", "play")

    /** Gibt sich die App als System-/Herstellerkomponente aus, ohne es zu sein? */
    fun impersonation(pkg: String, label: String, vendorVerified: Boolean, preinstalled: Boolean): String? {
        if (vendorVerified || preinstalled) return null
        claimedVendor(pkg)?.let { return "Paketname gibt $it als Hersteller an, die Signatur stammt aber nicht von $it" }
        val l = label.lowercase()
        val hit = IMPERSONATION_WORDS.firstOrNull { Regex("""\b$it\b""").containsMatchIn(l) }
        return hit?.let { "Name „$label“ klingt nach einer System-/Herstellerkomponente" }
    }
}
