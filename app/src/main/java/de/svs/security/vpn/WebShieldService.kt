package de.svs.security.vpn

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import de.svs.security.MainActivity
import de.svs.security.history.EventLog
import de.svs.security.history.LogEvent
import de.svs.security.intel.ThreatIntel
import de.svs.security.monitor.Notifier
import kotlinx.coroutines.runBlocking
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * Web-Schutz: lokales „VPN“, das ausschliesslich DNS-Anfragen pruefen laesst. Bekannte Malware-,
 * Phishing- und Betrugsseiten werden blockiert, bevor der Browser sie ueberhaupt laden kann.
 * Der normale Datenverkehr verlaesst das Handy unveraendert – es wird nichts mitgelesen oder umgeleitet.
 */
class WebShieldService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private var reader: Thread? = null
    private val pool = Executors.newFixedThreadPool(6)
    private val lastNotified = ConcurrentHashMap<String, Long>()
    private var upstreams: List<InetAddress> = emptyList()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopShield(); stopSelf(); return START_NOT_STICKY }
        if (!running) startShield()
        return START_STICKY
    }

    private fun startShield() {
        if (ThreatIntel.db.domainCount == 0) runBlocking { ThreatIntel.load(applicationContext) }
        upstreams = buildUpstreams()
        val configure = PendingIntent.getActivity(this, 1, Intent(this, MainActivity::class.java).putExtra("tab", "protect"), PendingIntent.FLAG_IMMUTABLE)
        val b = Builder()
            .setSession("SVS Web-Schutz")
            .addAddress(TUN_ADDR, 32)
            .addDnsServer(DNS_ADDR)
            .addRoute(DNS_ADDR, 32)
            .setBlocking(true)
            .setConfigureIntent(configure)
        runCatching { b.addDisallowedApplication(packageName) }
        tun = runCatching { b.establish() }.getOrNull()
        if (tun == null) { setEnabled(this, false); stopSelf(); return }
        running = true
        setEnabled(this, true)
        reader = Thread({ loop() }, "WebShield").apply { start() }
    }

    /** Upstream-DNS: Quad9 (filtert selbst zusaetzlich Malware), danach DNS des Netzes als Reserve. */
    private fun buildUpstreams(): List<InetAddress> {
        val list = mutableListOf<InetAddress>(InetAddress.getByName("9.9.9.9"), InetAddress.getByName("149.112.112.112"))
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.getLinkProperties(cm.activeNetwork)?.dnsServers?.filterIsInstance<Inet4Address>()
                ?.filter { it.hostAddress != DNS_ADDR }?.forEach { list += it }
        }
        return list
    }

    private fun loop() {
        val fd = tun ?: return
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val n = runCatching { input.read(buf) }.getOrElse { -1 }
            if (n < 0) break
            if (n == 0) continue
            val q = DnsPacket.parse(buf, n) ?: continue
            val host = q.name
            val threat = host?.takeUnless { isAllowed(this, it) }?.let { ThreatIntel.db.domainThreat(it) }
            if (threat != null) {
                write(output, DnsPacket.buildResponse(q, DnsPacket.nxdomain(q.dns)))
                onBlocked(host, threat)
            } else {
                pool.execute { forward(output, q) }
            }
        }
    }

    private fun forward(output: FileOutputStream, q: DnsPacket.Query) {
        for (server in upstreams) {
            val ok = runCatching {
                DatagramSocket().use { s ->
                    protect(s)
                    s.soTimeout = 4000
                    s.send(DatagramPacket(q.dns, q.dns.size, InetSocketAddress(server, 53)))
                    val resp = ByteArray(4096)
                    val p = DatagramPacket(resp, resp.size)
                    s.receive(p)
                    write(output, DnsPacket.buildResponse(q, resp.copyOf(p.length)))
                }
            }.isSuccess
            if (ok) return
        }
    }

    private fun write(out: FileOutputStream, pkt: ByteArray) = synchronized(this) { runCatching { out.write(pkt) } }

    private fun onBlocked(host: String, threat: String) {
        val p = getSharedPreferences(PREFS, MODE_PRIVATE)
        p.edit().putLong("blocked", p.getLong("blocked", 0) + 1).apply()
        val now = System.currentTimeMillis()
        val last = lastNotified[host] ?: 0
        if (now - last < 10 * 60_000) return
        lastNotified[host] = now
        EventLog.add(this, LogEvent(now, "BLOCKED", "Gefährliche Seite blockiert: $host", "Kategorie: $threat", alert = true))
        Notifier.warn(this, "Gefährliche Seite blockiert", "$host ($threat) wurde gesperrt, bevor sie geladen werden konnte.")
    }

    private fun stopShield() {
        running = false
        runCatching { tun?.close() }
        tun = null
        reader?.interrupt()
        setEnabled(this, false)
    }

    override fun onRevoke() { stopShield(); super.onRevoke() }
    override fun onDestroy() { stopShield(); pool.shutdownNow(); super.onDestroy() }

    companion object {
        const val ACTION_STOP = "de.svs.security.STOP_SHIELD"
        private const val TUN_ADDR = "10.111.222.2"
        const val DNS_ADDR = "10.111.222.1"
        private const val PREFS = "shield"

        fun isEnabled(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("on", false)
        fun wanted(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean("want", false)
        private fun setEnabled(ctx: Context, v: Boolean) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("on", v).apply()
        fun blockedCount(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong("blocked", 0)

        fun allowlist(ctx: Context): Set<String> = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getStringSet("allow", emptySet()).orEmpty()
        fun setAllowed(ctx: Context, host: String, allowed: Boolean) {
            val s = allowlist(ctx).toMutableSet()
            if (allowed) s += host.lowercase() else s -= host.lowercase()
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putStringSet("allow", s).apply()
        }
        fun isAllowed(ctx: Context, host: String): Boolean {
            val a = allowlist(ctx)
            if (a.isEmpty()) return false
            return a.any { host == it || host.endsWith(".$it") }
        }

        fun start(ctx: Context) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("want", true).apply()
            ctx.startService(Intent(ctx, WebShieldService::class.java))
        }

        fun stop(ctx: Context) {
            ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean("want", false).apply()
            ctx.startService(Intent(ctx, WebShieldService::class.java).setAction(ACTION_STOP))
        }
    }
}
