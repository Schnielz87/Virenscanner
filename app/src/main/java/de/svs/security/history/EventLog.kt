package de.svs.security.history

import android.content.Context
import org.json.JSONObject
import java.io.File

/** Ein Ereignis in der Chronik. */
data class LogEvent(
    val time: Long,
    /** z. B. INSTALL, UPDATE, REMOVED, DATA_CLEARED, BOOT, SAFE_MODE, BLOCKED, ROLE, SCAN, USAGE … */
    val type: String,
    val title: String,
    val detail: String = "",
    val pkg: String? = null,
    /** true = auffaellig (rot markieren) */
    val alert: Boolean = false,
)

/**
 * Dauerhaftes Protokoll der App (ab Installation). Android selbst speichert keine Chronik von
 * Widget-Aenderungen o. ae. – deshalb zeichnet die App ab jetzt alles Wichtige selbst auf.
 */
object EventLog {
    private const val MAX_EVENTS = 5000
    private val lock = Any()

    private fun file(ctx: Context) = File(ctx.filesDir, "events.jsonl")

    fun add(ctx: Context, e: LogEvent) = synchronized(lock) {
        val f = file(ctx)
        f.appendText(toJson(e).toString() + "\n")
        // gelegentlich kuerzen
        if (f.length() > 2_000_000) {
            val lines = f.readLines().takeLast(MAX_EVENTS)
            f.writeText(lines.joinToString("\n", postfix = "\n"))
        }
    }

    fun all(ctx: Context): List<LogEvent> = synchronized(lock) {
        val f = file(ctx)
        if (!f.exists()) return emptyList()
        f.readLines().mapNotNull { l -> runCatching { fromJson(JSONObject(l)) }.getOrNull() }
    }

    fun between(ctx: Context, from: Long, to: Long) = all(ctx).filter { it.time in from..to }

    fun clear(ctx: Context) = synchronized(lock) { file(ctx).delete(); Unit }

    private fun toJson(e: LogEvent) = JSONObject().put("t", e.time).put("y", e.type).put("ti", e.title)
        .put("d", e.detail).put("p", e.pkg ?: "").put("a", e.alert)

    private fun fromJson(o: JSONObject) = LogEvent(
        o.getLong("t"), o.getString("y"), o.getString("ti"), o.optString("d"), o.optString("p").ifEmpty { null }, o.optBoolean("a"),
    )
}
