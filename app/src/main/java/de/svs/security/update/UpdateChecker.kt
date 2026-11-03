package de.svs.security.update

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import de.svs.security.Http
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.IOException

data class ReleaseInfo(val title: String, val build: Int, val notes: String, val apkUrl: String?, val pageUrl: String)

/**
 * Updates direkt von GitHub (wie bei den anderen Apps): Release pruefen, APK laden, Android-Installer oeffnen.
 * Jede APK ist mit demselben Schluessel signiert – Einstellungen und Protokoll bleiben beim Update erhalten.
 *
 * Oeffentliches Repository Schnielz87/Virenscanner: die Pruefung funktioniert ohne GitHub-Anmeldung.
 */
object UpdateChecker {
    const val REPO = "Schnielz87/Virenscanner"
    const val TAG = "neueste-version"
    const val ASSET = "SVS-Security.apk"
    val PAGE_URL = "https://github.com/$REPO/releases/tag/$TAG"
    val DIRECT_URL = "https://github.com/$REPO/releases/download/$TAG/$ASSET"

    /** "SVS Security v1.0.42" / "1.0.42" -> 42 */
    fun buildOf(s: String?): Int? = s?.let { Regex("""(\d+)\.(\d+)\.(\d+)""").find(it) }?.groupValues?.get(3)?.toIntOrNull()

    fun currentVersion(ctx: Context): String =
        runCatching { ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName }.getOrNull() ?: "?"

    fun currentBuild(ctx: Context) = buildOf(currentVersion(ctx)) ?: 0

    suspend fun latest(): ReleaseInfo = withContext(Dispatchers.IO) {
        val text = try {
            Http.getText("https://api.github.com/repos/$REPO/releases/tags/$TAG", "application/vnd.github+json")
        } catch (e: IOException) {
            if (e.message?.contains("404") == true) throw IOException("Noch keine Version veröffentlicht – bitte später erneut versuchen.")
            throw e
        }
        val o = JSONObject(text)
        val name = o.optString("name").ifEmpty { o.optString("tag_name") }
        val assets = o.optJSONArray("assets")
        var apk: String? = null
        if (assets != null) for (i in 0 until assets.length()) {
            val a = assets.getJSONObject(i)
            if (a.optString("name") == ASSET || (apk == null && a.optString("name").endsWith(".apk"))) apk = a.optString("browser_download_url")
        }
        ReleaseInfo(name, buildOf(name) ?: buildOf(o.optString("body")) ?: 0, o.optString("body"), apk, o.optString("html_url").ifEmpty { PAGE_URL })
    }

    fun canInstall(ctx: Context) = Build.VERSION.SDK_INT < 26 || ctx.packageManager.canRequestPackageInstalls()

    fun openInstallPermission(ctx: Context) {
        if (Build.VERSION.SDK_INT >= 26) ctx.startActivity(
            Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }

    suspend fun download(ctx: Context, r: ReleaseInfo): File = withContext(Dispatchers.IO) {
        val url = r.apkUrl ?: throw IOException("Keine APK im Release")
        val f = File(ctx.cacheDir, "update/$ASSET").apply { parentFile?.mkdirs() }
        f.writeBytes(Http.get(url, maxBytes = 200L * 1024 * 1024))
        f
    }

    fun install(ctx: Context, file: File) {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.updates", file)
        ctx.startActivity(
            Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK),
        )
    }

    fun openInBrowser(ctx: Context) = ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(PAGE_URL)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}
