package de.svs.security.vpn

/**
 * IPv4/UDP/DNS-Pakete lesen und bauen – reine Logik fuer den Web-Schutz (Unit-Tests in DnsPacketTest).
 * Es werden nur DNS-Anfragen verarbeitet; der restliche Internetverkehr laeuft NICHT durch die App.
 */
object DnsPacket {

    class Query(
        val srcIp: ByteArray, val dstIp: ByteArray,
        val srcPort: Int, val dstPort: Int,
        /** Nur der DNS-Teil (ab DNS-Header) */
        val dns: ByteArray,
        val name: String?,
    )

    /** Liefert die Anfrage, falls [pkt] ein IPv4-UDP-Paket an Port 53 ist. */
    fun parse(pkt: ByteArray, len: Int = pkt.size): Query? {
        if (len < 28) return null
        val version = (pkt[0].toInt() ushr 4) and 0xF
        if (version != 4) return null
        val ihl = (pkt[0].toInt() and 0xF) * 4
        if (ihl < 20 || len < ihl + 8) return null
        if ((pkt[9].toInt() and 0xFF) != 17) return null // nur UDP
        val total = u16(pkt, 2).coerceAtMost(len)
        val srcPort = u16(pkt, ihl)
        val dstPort = u16(pkt, ihl + 2)
        if (dstPort != 53) return null
        val udpLen = u16(pkt, ihl + 4)
        val dnsLen = (minOf(udpLen, total - ihl)) - 8
        if (dnsLen < 12) return null
        val dns = pkt.copyOfRange(ihl + 8, ihl + 8 + dnsLen)
        return Query(pkt.copyOfRange(12, 16), pkt.copyOfRange(16, 20), srcPort, dstPort, dns, queryName(dns))
    }

    /** Erster Name im Fragebereich, z. B. "www.example.com". */
    fun queryName(dns: ByteArray): String? {
        if (dns.size < 12 || u16(dns, 4) < 1) return null
        val sb = StringBuilder()
        var i = 12
        while (i < dns.size) {
            val l = dns[i].toInt() and 0xFF
            if (l == 0) return sb.toString().lowercase()
            if (l and 0xC0 != 0) return null // Kompression in Anfragen nicht erwartet
            if (i + 1 + l > dns.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (k in 1..l) sb.append((dns[i + k].toInt() and 0xFF).toChar())
            i += l + 1
        }
        return null
    }

    /** Ende des ersten Fragebereichs (nach QTYPE/QCLASS) oder -1. */
    private fun questionEnd(dns: ByteArray): Int {
        var i = 12
        while (i < dns.size) {
            val l = dns[i].toInt() and 0xFF
            if (l == 0) return (i + 5).takeIf { it <= dns.size } ?: -1
            if (l and 0xC0 != 0) return -1
            i += l + 1
        }
        return -1
    }

    /** DNS-Antwort „Domain existiert nicht“ (NXDOMAIN) auf eine Anfrage. */
    fun nxdomain(query: ByteArray): ByteArray {
        val end = questionEnd(query)
        val r = if (end > 0) query.copyOf(end) else query.copyOf(12)
        r[2] = (0x80 or (query[2].toInt() and 0x79)).toByte()   // QR=1, Opcode+RD uebernehmen
        r[3] = (0x80 or 3).toByte()                              // RA=1, RCODE=3
        put16(r, 4, if (end > 0) 1 else 0)                       // QDCOUNT
        put16(r, 6, 0); put16(r, 8, 0); put16(r, 10, 0)
        return r
    }

    /** IPv4/UDP-Antwortpaket an den Absender der Anfrage [q] mit DNS-Inhalt [dns]. */
    fun buildResponse(q: Query, dns: ByteArray): ByteArray {
        val total = 20 + 8 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45
        put16(p, 2, total)
        put16(p, 4, 0)            // Identification
        p[6] = 0x40               // Don't fragment
        p[8] = 64                 // TTL
        p[9] = 17                 // UDP
        System.arraycopy(q.dstIp, 0, p, 12, 4)  // Absender = urspruengliches Ziel (DNS-Server)
        System.arraycopy(q.srcIp, 0, p, 16, 4)
        put16(p, 10, ipChecksum(p, 0, 20))
        put16(p, 20, q.dstPort)
        put16(p, 22, q.srcPort)
        put16(p, 24, 8 + dns.size)
        put16(p, 26, 0)           // UDP-Pruefsumme optional bei IPv4
        System.arraycopy(dns, 0, p, 28, dns.size)
        return p
    }

    fun ipChecksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len) {
            if (i == off + 10) { i += 2; continue } // Pruefsummenfeld selbst auslassen
            sum += ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return (sum.inv() and 0xFFFF).toInt()
    }

    fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun put16(b: ByteArray, o: Int, v: Int) { b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte() }

    /** Testhilfe/Builder: DNS-Anfrage fuer [name] (Typ A). */
    fun buildQuery(id: Int, name: String): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        out.write(id ushr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00) // RD
        out.write(0); out.write(1); repeat(6) { out.write(0) }
        name.split('.').forEach { l -> out.write(l.length); out.write(l.toByteArray()) }
        out.write(0)
        out.write(0); out.write(1); out.write(0); out.write(1)
        return out.toByteArray()
    }

    /** Testhilfe: IPv4/UDP-Paket mit DNS-Inhalt bauen. */
    fun wrap(src: ByteArray, dst: ByteArray, srcPort: Int, dns: ByteArray): ByteArray {
        val q = Query(dst, src, 53, srcPort, ByteArray(0), null)
        return buildResponse(q, dns).also { put16(it, 20, srcPort); put16(it, 22, 53) }
    }
}
