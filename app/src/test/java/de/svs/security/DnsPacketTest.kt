package de.svs.security

import de.svs.security.vpn.DnsPacket
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DnsPacketTest {
    private val client = byteArrayOf(10, 111, 222.toByte(), 2)
    private val dnsServer = byteArrayOf(10, 111, 222.toByte(), 1)

    @Test fun parseQuery() {
        val dns = DnsPacket.buildQuery(0x1234, "www.Evil.com")
        val pkt = DnsPacket.wrap(client, dnsServer, 40000, dns)
        val q = DnsPacket.parse(pkt)
        assertNotNull(q)
        assertEquals("www.evil.com", q!!.name)
        assertEquals(40000, q.srcPort)
        assertEquals(53, q.dstPort)
        assertArrayEquals(dns, q.dns)
    }

    @Test fun ignoresNonDns() {
        val pkt = DnsPacket.wrap(client, dnsServer, 40000, DnsPacket.buildQuery(1, "a.de"))
        pkt[23] = 80 // Zielport 80
        assertNull(DnsPacket.parse(pkt))
        val tcp = DnsPacket.wrap(client, dnsServer, 40000, DnsPacket.buildQuery(1, "a.de")).also { it[9] = 6 }
        assertNull(DnsPacket.parse(tcp))
    }

    @Test fun nxdomainResponse() {
        val dns = DnsPacket.buildQuery(0xBEEF, "bad.example")
        val q = DnsPacket.parse(DnsPacket.wrap(client, dnsServer, 5555, dns))!!
        val r = DnsPacket.nxdomain(q.dns)
        assertEquals(0xBE, r[0].toInt() and 0xFF)
        assertEquals(0xEF, r[1].toInt() and 0xFF)
        assertEquals(0x81, r[2].toInt() and 0xFF) // QR + RD
        assertEquals(0x83, r[3].toInt() and 0xFF) // RA + NXDOMAIN
        assertEquals(dns.size, r.size)
        val ip = DnsPacket.buildResponse(q, r)
        assertArrayEquals(dnsServer, ip.copyOfRange(12, 16))
        assertArrayEquals(client, ip.copyOfRange(16, 20))
        assertEquals(53, DnsPacket.u16(ip, 20))
        assertEquals(5555, DnsPacket.u16(ip, 22))
        assertEquals(ip.size, DnsPacket.u16(ip, 2))
        // Pruefsumme stimmt: Summe ueber Header inkl. Pruefsumme = 0xFFFF
        var sum = 0
        for (i in 0 until 20 step 2) sum += DnsPacket.u16(ip, i)
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }
}
