package de.svs.security.intel

import android.content.Context
import de.svs.security.Http
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.io.File

/** Eine Bedrohungsdaten-Quelle aus dem Netz. */
data class IntelSource(
    val id: String,
    val title: String,
    val description: String,
    val url: String,
    /** Mindestgroesse in Bytes, damit eine kaputte/leere Antwort die alten Daten nicht ersetzt. */
    val minBytes: Int,
)

data class IntelStatus(
    val lastUpdate: Long,
    val lastError: String?,
    val families: Int,
    val packages: Int,
    val certificates: Int,
    val hashes: Int,
    val domains: Int,
    val news: List<NewsItem>,
)

/**
 * Laedt taeglich die aktuellen Bedrohungsdaten aus dem Netz und haelt sie lokal vor ("manifestiert").
 * Ohne Internet gelten die zuletzt geladenen Daten bzw. der in der App mitgelieferte Grundstock.
 */
object ThreatIntel {

    val SOURCES = listOf(
        IntelSource(
            "stalkerware_ioc.yaml", "Spionage-Apps (Stalkerware)",
            "Paketnamen, Signatur-Zertifikate und Server bekannter Spionage-Apps – Echap / Coalition Against Stalkerware",
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml", 20_000,
        ),
        IntelSource(
            "stalkerware_samples.csv", "Schad-APK-Fingerabdrücke",
            "SHA-256-Prüfsummen bekannter Spionage-APKs – Echap",
            "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/samples.csv", 50_000,
        ),
        IntelSource(
            "malware_domains.txt", "Malware-Webseiten",
            "Webseiten, die aktuell Schadsoftware verteilen – abuse.ch URLhaus (über malware-filter)",
            "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt", 20_000,
        ),
        IntelSource(
            "phishing_domains.txt", "Phishing- & Betrugsseiten",
            "Aktive Phishing-/Betrugsseiten – OpenPhish, IPThreat, PhishTank (über malware-filter)",
            "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt", 50_000,
        ),
        IntelSource(
            "bsi_wid.xml", "BSI-Sicherheitswarnungen",
            "Warn- und Informationsdienst des Bundesamts für Sicherheit in der Informationstechnik",
            "https://wid.cert-bund.de/content/public/securityAdvisory/rss", 2_000,
        ),
    )

    @Volatile var db: ThreatDb = ThreatDb.EMPTY
        private set

    private val _status = MutableStateFlow(IntelStatus(0, null, 0, 0, 0, 0, 0, emptyList()))
    val status: StateFlow<IntelStatus> = _status

    private fun dir(ctx: Context) = File(ctx.filesDir, "intel").apply { mkdirs() }
    private fun prefs(ctx: Context) = ctx.getSharedPreferences("intel", Context.MODE_PRIVATE)

    /** Text einer Quelle: heruntergeladene Fassung, sonst mitgelieferter Grundstock. */
    private fun read(ctx: Context, id: String): String {
        val f = File(dir(ctx), id)
        if (f.exists() && f.length() > 0) return f.readText()
        return runCatching { ctx.assets.open("intel/$id").bufferedReader().use { it.readText() } }.getOrDefault("")
    }

    /** Daten in den Speicher laden (beim App-Start, nach Updates). */
    suspend fun load(ctx: Context) = withContext(Dispatchers.Default) {
        val families = Parsers.parseIocYaml(read(ctx, "stalkerware_ioc.yaml"))
        val samples = Parsers.parseSamplesCsv(read(ctx, "stalkerware_samples.csv"))
        val malware = Parsers.parseDomainList(read(ctx, "malware_domains.txt"))
        val phishing = Parsers.parseDomainList(read(ctx, "phishing_domains.txt"))
        val news = Parsers.parseRss(read(ctx, "bsi_wid.xml"))
        val d = ThreatDb(families, samples, malware, phishing)
        db = d
        val p = prefs(ctx)
        _status.value = IntelStatus(
            lastUpdate = p.getLong("last", 0L),
            lastError = p.getString("error", null),
            families = d.familyCount,
            packages = d.packages.size,
            certificates = d.certificates.size,
            hashes = d.hashes.size,
            domains = d.domainCount,
            news = news,
        )
    }

    /** Alle Quellen neu laden. Liefert die Anzahl erfolgreich geladener Quellen. */
    suspend fun update(ctx: Context): Int = withContext(Dispatchers.IO) {
        var ok = 0
        val errors = mutableListOf<String>()
        for (s in SOURCES) {
            runCatching {
                val bytes = Http.get(s.url)
                require(bytes.size >= s.minBytes) { "Antwort zu klein (${bytes.size} Bytes)" }
                val tmp = File(dir(ctx), s.id + ".part")
                tmp.writeBytes(bytes)
                val target = File(dir(ctx), s.id)
                if (!tmp.renameTo(target)) { tmp.copyTo(target, overwrite = true); tmp.delete() }
                ok++
            }.onFailure { errors += "${s.title}: ${it.message}" }
        }
        prefs(ctx).edit().apply {
            if (ok > 0) putLong("last", System.currentTimeMillis())
            putString("error", errors.joinToString("\n").ifEmpty { null })
        }.apply()
        load(ctx)
        ok
    }
}
