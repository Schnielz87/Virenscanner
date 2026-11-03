package de.svs.security.intel

/**
 * Reine Text-Parser fuer die Bedrohungsdaten (ohne Android-Abhaengigkeiten -> per Unit-Test pruefbar).
 */

/** Indikatoren eines bekannten Spionage-/Schadprogramms. */
data class IocFamily(
    val name: String,
    val type: String,
    val packages: Set<String>,
    val certificates: Set<String>,
    val domains: Set<String>,
)

data class SampleIoc(val sha256: String, val pkg: String, val cert: String, val app: String)

data class NewsItem(val title: String, val link: String, val description: String, val severity: String, val pubDate: String)

object Parsers {

    /**
     * Liest die stalkerware-indicators ioc.yaml (Echap). Bewusst ohne YAML-Bibliothek:
     * das Format ist einfach (Liste von Eintraegen, darin Listen und c2.domains/c2.ips).
     */
    fun parseIocYaml(text: String): List<IocFamily> {
        val out = mutableListOf<IocFamily>()
        var name: String? = null
        var type = "stalkerware"
        val pk = mutableSetOf<String>(); val ce = mutableSetOf<String>(); val dom = mutableSetOf<String>()
        var top: String? = null
        var nested: String? = null

        fun flush() {
            val n = name ?: return
            out += IocFamily(n, type, pk.toSet(), ce.toSet(), dom.toSet())
            pk.clear(); ce.clear(); dom.clear(); type = "stalkerware"
        }

        for (raw in text.lineSequence()) {
            if (raw.isBlank() || raw.trimStart().startsWith("#")) continue
            val indent = raw.length - raw.trimStart().length
            val line = raw.trim()
            if (indent == 0 && line.startsWith("- name:")) {
                flush()
                name = clean(line.removePrefix("- name:"))
                top = null; nested = null
                continue
            }
            if (line.startsWith("- ")) {
                val v = clean(line.removePrefix("- "))
                if (v.isEmpty()) continue
                val key = if (indent >= 4 && nested != null) "$top.$nested" else top
                when (key) {
                    "packages" -> pk += v
                    "certificates" -> ce += v.uppercase().replace(":", "")
                    "websites", "distribution", "c2.domains" -> dom += v.lowercase()
                }
                continue
            }
            if (line.endsWith(":") || line.contains(": ")) {
                val k = line.substringBefore(":").trim()
                val value = clean(line.substringAfter(":", ""))
                if (indent <= 2) {
                    top = k; nested = null
                    if (k == "type" && value.isNotEmpty()) type = value
                    if (k == "name" && value.isNotEmpty()) name = value
                } else {
                    nested = k
                }
            }
        }
        flush()
        return out
    }

    /** samples.csv: SHA256,Package Name,Certificate,Version,App */
    fun parseSamplesCsv(text: String): List<SampleIoc> =
        text.lineSequence().drop(1).mapNotNull { l ->
            val p = l.split(',')
            if (p.size < 5) return@mapNotNull null
            val sha = p[0].trim().lowercase()
            if (sha.length != 64) return@mapNotNull null
            SampleIoc(sha, p[1].trim(), p[2].trim().uppercase(), p.drop(4).joinToString(",").trim())
        }.toList()

    /** Domainliste: eine Domain je Zeile, Kommentare mit '#' oder '!'. Auch Hosts-Format "0.0.0.0 domain". */
    fun parseDomainList(text: String): Set<String> {
        val out = HashSet<String>(32_000)
        for (raw in text.lineSequence()) {
            var l = raw.trim()
            if (l.isEmpty() || l.startsWith("#") || l.startsWith("!")) continue
            val parts = l.split(Regex("\\s+"))
            l = if (parts.size >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1")) parts[1] else parts[0]
            l = l.lowercase().trimEnd('.')
            if (l.isNotEmpty() && l != "localhost") out += l
        }
        return out
    }

    /** Einfacher RSS-2.0-Parser fuer den BSI-Warndienst. */
    fun parseRss(xml: String, limit: Int = 200): List<NewsItem> {
        val items = Regex("<item>(.*?)</item>", RegexOption.DOT_MATCHES_ALL).findAll(xml)
        return items.take(limit).map { m ->
            val b = m.groupValues[1]
            NewsItem(
                title = tag(b, "title"),
                link = tag(b, "link"),
                description = tag(b, "description"),
                severity = tag(b, "category"),
                pubDate = tag(b, "pubDate"),
            )
        }.toList()
    }

    /** Meldungen, die fuer ein Android-/Samsung-Handy relevant sind. */
    fun isMobileRelevant(n: NewsItem): Boolean {
        val t = (n.title + " " + n.description).lowercase()
        return MOBILE_KEYWORDS.any { it in t }
    }

    private val MOBILE_KEYWORDS = listOf(
        "android", "samsung", "google chrome", "chromium", "whatsapp", "qualcomm", "mediatek",
        "exynos", "smartphone", "mobile", "pixel", "firefox", "webview",
    )

    private fun tag(block: String, name: String): String {
        val m = Regex("<$name>(.*?)</$name>", RegexOption.DOT_MATCHES_ALL).find(block) ?: return ""
        return unescape(m.groupValues[1].trim().removePrefix("<![CDATA[").removeSuffix("]]>").trim())
    }

    private fun unescape(s: String) = s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
        .replace("&#39;", "'").replace("&apos;", "'").replace("&amp;", "&")

    private fun clean(s: String) = s.trim().trim('"', '\'').trim()
}
