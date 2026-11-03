package de.svs.security.intel

/**
 * Bedrohungsdatenbank im Speicher. Reine Logik, keine Android-Abhaengigkeit.
 */
class ThreatDb(
    families: List<IocFamily>,
    samples: List<SampleIoc>,
    malwareDomains: Set<String>,
    phishingDomains: Set<String>,
) {
    /** Paketname -> Name des Schadprogramms */
    val packages: Map<String, String>
    /** Zertifikat SHA-1 (gross, ohne ':') -> Name */
    val certificates: Map<String, String>
    /** APK SHA-256 (klein) -> Name */
    val hashes: Map<String, String>
    /** Domain -> Kategorie ("Malware", "Phishing", "Spionage-App") */
    private val domains: HashMap<String, String>

    init {
        val p = HashMap<String, String>(); val c = HashMap<String, String>(); val h = HashMap<String, String>()
        val d = HashMap<String, String>(malwareDomains.size + phishingDomains.size + 2000)
        for (f in families) {
            f.packages.forEach { p[it] = f.name }
            f.certificates.forEach { c[it] = f.name }
            f.domains.forEach { d[it] = "Spionage-App ${f.name}" }
        }
        for (s in samples) {
            h[s.sha256] = s.app
            if (s.pkg.isNotBlank()) p.putIfAbsent(s.pkg, s.app)
            if (s.cert.isNotBlank()) c.putIfAbsent(s.cert, s.app)
        }
        phishingDomains.forEach { d[it] = "Phishing" }
        malwareDomains.forEach { d[it] = "Malware" }
        packages = p; certificates = c; hashes = h; domains = d
    }

    val familyCount = families.size
    val domainCount get() = domains.size

    /**
     * Prueft eine Domain inkl. uebergeordneter Domains (a.b.evil.com -> b.evil.com -> evil.com).
     * Liefert die Kategorie oder null.
     */
    fun domainThreat(host: String): String? {
        var h = host.lowercase().trim().trimEnd('.')
        if (h.isEmpty()) return null
        while (true) {
            domains[h]?.let { return it }
            val i = h.indexOf('.')
            if (i < 0 || i == h.length - 1) return null
            h = h.substring(i + 1)
            if (!h.contains('.')) return null // keine Top-Level-Domain allein pruefen
        }
    }

    fun packageThreat(pkg: String): String? = packages[pkg]
    fun certThreat(sha1: String): String? = certificates[sha1.uppercase().replace(":", "")]
    fun hashThreat(sha256: String): String? = hashes[sha256.lowercase()]

    companion object {
        val EMPTY = ThreatDb(emptyList(), emptyList(), emptySet(), emptySet())

        /** Host aus einem Link oder Text holen ("https://x.y/z" -> "x.y"). */
        fun hostOf(input: String): String? {
            var s = input.trim()
            val m = Regex("""https?://[^\s"'<>]+""", RegexOption.IGNORE_CASE).find(s)
            if (m != null) s = m.value
            s = s.substringAfter("://")
            s = s.substringBefore('/').substringBefore('?').substringBefore('#')
            s = s.substringAfter('@').substringBefore(':')
            s = s.lowercase().trimEnd('.')
            return s.takeIf { it.contains('.') && it.none { c -> c.isWhitespace() } }
        }
    }
}
