package de.svs.security

import de.svs.security.intel.Parsers
import de.svs.security.intel.ThreatDb
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ParsersTest {
    private val assets = File("src/main/assets/intel")

    @Test fun iocYamlSnippet() {
        val y = """
- name: TheTruthSpy
  names:
  - Copy9
  type: stalkerware
  packages:
  - com.apspy.app
  - com.fone
  certificates:
  - 31A6ECECD97CF39BC4126B8745CD94A7C30BF81C
  websites:
  - copy9.com
  c2:
    ips:
    - 69.64.74.239
    domains:
    - 1ca43.appspot.com
- name: Other
  packages:
  - "com.other.spy"
""".trimIndent()
        val f = Parsers.parseIocYaml(y)
        assertEquals(2, f.size)
        assertEquals(setOf("com.apspy.app", "com.fone"), f[0].packages)
        assertEquals(setOf("31A6ECECD97CF39BC4126B8745CD94A7C30BF81C"), f[0].certificates)
        assertEquals(setOf("copy9.com", "1ca43.appspot.com"), f[0].domains)
        assertEquals(setOf("com.other.spy"), f[1].packages)
    }

    @Test fun bundledDataParses() {
        val fam = Parsers.parseIocYaml(File(assets, "stalkerware_ioc.yaml").readText())
        assertTrue("families ${fam.size}", fam.size > 100)
        assertTrue(fam.sumOf { it.packages.size } > 200)
        val samples = Parsers.parseSamplesCsv(File(assets, "stalkerware_samples.csv").readText())
        assertTrue("samples ${samples.size}", samples.size > 1000)
        val mal = Parsers.parseDomainList(File(assets, "malware_domains.txt").readText())
        val phi = Parsers.parseDomainList(File(assets, "phishing_domains.txt").readText())
        assertTrue(mal.size > 5000 && phi.size > 5000)
        val db = ThreatDb(fam, samples, mal, phi)
        assertEquals("TheTruthSpy", db.packageThreat("com.apspy.app"))
        assertTrue(db.domainThreat("sub.copy9.com")!!.startsWith("Spionage"))
        assertNull(db.domainThreat("google.com"))
        assertNull(db.domainThreat("svs.de"))
        val anyMal = mal.first { it.count { c -> c == '.' } >= 1 && !it[0].isDigit() }
        assertEquals("Malware", db.domainThreat("www.$anyMal"))
    }

    @Test fun rss() {
        val x = """<rss><channel><item><title>[NEU] [hoch] Google Android: Mehrere Schwachstellen</title>
            <link>https://x/1</link><description>Ein Angreifer &amp; mehr</description><category>hoch</category>
            <pubDate>Tue, 03 Nov 2026 10:25:40 GMT</pubDate></item><item><title>QT: DoS</title><link>l</link>
            <description>d</description><category>mittel</category><pubDate>p</pubDate></item></channel></rss>"""
        val n = Parsers.parseRss(x)
        assertEquals(2, n.size)
        assertEquals("Ein Angreifer & mehr", n[0].description)
        assertTrue(Parsers.isMobileRelevant(n[0]))
        assertTrue(!Parsers.isMobileRelevant(n[1]))
    }

    @Test fun hostOf() {
        assertEquals("evil.example.com", ThreatDb.hostOf("Schau mal https://Evil.Example.com/login?x=1"))
        assertEquals("a.b.de", ThreatDb.hostOf("a.b.de/pfad"))
        assertEquals("x.de", ThreatDb.hostOf("http://user@x.de:8080/"))
        assertNull(ThreatDb.hostOf("kein link"))
    }
}
