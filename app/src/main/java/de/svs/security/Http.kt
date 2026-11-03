package de.svs.security

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Minimaler HTTPS-Client (ohne Zusatzbibliothek), folgt Weiterleitungen. */
object Http {
    private const val UA = "SVS-Security-Android"

    fun get(url: String, accept: String? = null, maxBytes: Long = 30L * 1024 * 1024): ByteArray {
        var current = url
        repeat(5) {
            val c = (URL(current).openConnection() as HttpURLConnection).apply {
                connectTimeout = 20_000
                readTimeout = 60_000
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", UA)
                if (accept != null) setRequestProperty("Accept", accept)
            }
            try {
                val code = c.responseCode
                if (code in 300..399) {
                    val loc = c.getHeaderField("Location") ?: throw IOException("Weiterleitung ohne Ziel")
                    current = URL(URL(current), loc).toString()
                    require(current.startsWith("https://")) { "Unsichere Weiterleitung" }
                    return@repeat
                }
                if (code == 403 || code == 429) throw IOException("Server ausgelastet (HTTP $code) – später erneut versuchen")
                if (code !in 200..299) throw IOException("HTTP $code")
                c.inputStream.use { input ->
                    val out = java.io.ByteArrayOutputStream()
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > maxBytes) throw IOException("Antwort zu groß")
                        out.write(buf, 0, n)
                    }
                    return out.toByteArray()
                }
            } finally {
                c.disconnect()
            }
        }
        throw IOException("Zu viele Weiterleitungen")
    }

    fun getText(url: String, accept: String? = null) = String(get(url, accept), Charsets.UTF_8)
}
