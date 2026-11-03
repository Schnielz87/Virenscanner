package de.svs.security.scan

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.AppOpsManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.provider.Telephony
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationManagerCompat
import java.io.File
import java.security.MessageDigest

/** Liest alle installierten Apps samt Rollen und Rechten aus (braucht QUERY_ALL_PACKAGES). */
object AppInventory {

    /** APKs bis zu dieser Groesse werden gehasht (Abgleich mit Schad-APK-Fingerabdruecken). */
    private const val MAX_HASH_BYTES = 200L * 1024 * 1024

    fun packages(ctx: Context): List<PackageInfo> {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_PERMISSIONS or
            (if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else @Suppress("DEPRECATION") PackageManager.GET_SIGNATURES)
        return if (Build.VERSION.SDK_INT >= 33) pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        else @Suppress("DEPRECATION") pm.getInstalledPackages(flags)
    }

    fun installerOf(pm: PackageManager, pkg: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
        else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
    }.getOrNull()

    fun isSystem(ai: ApplicationInfo?) = ai != null && (ai.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0

    fun accessibilityPackages(ctx: Context): Set<String> {
        val fromSettings = runCatching {
            Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
                ?.split(':')?.mapNotNull { it.substringBefore('/').takeIf { p -> p.isNotBlank() } }?.toSet()
        }.getOrNull().orEmpty()
        val fromManager = runCatching {
            (ctx.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager)
                .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }.toSet()
        }.getOrNull().orEmpty()
        return fromSettings + fromManager
    }

    fun deviceAdminPackages(ctx: Context): Set<String> = runCatching {
        (ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager).activeAdmins?.map { it.packageName }?.toSet()
    }.getOrNull().orEmpty()

    fun notificationListenerPackages(ctx: Context): Set<String> =
        runCatching { NotificationManagerCompat.getEnabledListenerPackages(ctx) }.getOrNull().orEmpty()

    fun defaultHome(ctx: Context): String? = runCatching {
        ctx.packageManager.resolveActivity(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), PackageManager.MATCH_DEFAULT_ONLY)
            ?.activityInfo?.packageName?.takeIf { it != "android" }
    }.getOrNull()

    private fun launcherPackages(pm: PackageManager): Set<String> = runCatching {
        pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), PackageManager.MATCH_ALL)
            .map { it.activityInfo.packageName }.toSet()
    }.getOrNull().orEmpty()

    private fun overlayAllowed(ctx: Context, ai: ApplicationInfo, requested: Boolean): Boolean {
        if (!requested) return false
        return runCatching {
            val ops = ctx.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow("android:system_alert_window", ai.uid, ai.packageName)
            else @Suppress("DEPRECATION") ops.checkOpNoThrow("android:system_alert_window", ai.uid, ai.packageName)
            mode == AppOpsManager.MODE_ALLOWED
        }.getOrDefault(false)
    }

    fun certSha1(pi: PackageInfo): List<String> = runCatching {
        val sigs = if (Build.VERSION.SDK_INT >= 28) {
            val si = pi.signingInfo ?: return@runCatching emptyList()
            if (si.hasMultipleSigners()) si.apkContentsSigners else si.signingCertificateHistory
        } else @Suppress("DEPRECATION") pi.signatures
        sigs.orEmpty().map { hex(MessageDigest.getInstance("SHA-1").digest(it.toByteArray())) }
    }.getOrDefault(emptyList())

    fun sha256(file: File): String? = runCatching {
        if (!file.canRead() || file.length() > MAX_HASH_BYTES) return null
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered(1 shl 16).use { input ->
            val buf = ByteArray(1 shl 16)
            while (true) { val n = input.read(buf); if (n < 0) break; md.update(buf, 0, n) }
        }
        hex(md.digest()).lowercase()
    }.getOrNull()

    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    /**
     * Erfasst alle Apps. Systemapps werden nicht gehasht (gross, aus dem Werk), Nutzer-Apps schon.
     * [onProgress] erhaelt (fertig, gesamt).
     */
    fun collect(ctx: Context, hashUserApps: Boolean, onProgress: (Int, Int) -> Unit = { _, _ -> }): List<AppInfo> {
        val pm = ctx.packageManager
        val pkgs = packages(ctx)
        val acc = accessibilityPackages(ctx)
        val admins = deviceAdminPackages(ctx)
        val listeners = notificationListenerPackages(ctx)
        val sms = runCatching { Telephony.Sms.getDefaultSmsPackage(ctx) }.getOrNull()
        val home = defaultHome(ctx)
        val launchers = launcherPackages(pm)
        return pkgs.mapIndexed { i, pi ->
            onProgress(i + 1, pkgs.size)
            val ai = pi.applicationInfo
            val system = isSystem(ai)
            val requested = pi.requestedPermissions.orEmpty()
            val flags = pi.requestedPermissionsFlags
            val granted = requested.filterIndexed { idx, _ ->
                flags != null && idx < flags.size && (flags[idx] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
            }.toSet()
            AppInfo(
                pkg = pi.packageName,
                label = ai?.let { runCatching { pm.getApplicationLabel(it).toString() }.getOrNull() } ?: pi.packageName,
                system = system,
                installer = installerOf(pm, pi.packageName),
                firstInstall = pi.firstInstallTime,
                lastUpdate = pi.lastUpdateTime,
                versionName = pi.versionName,
                sha256 = if (hashUserApps && !system && ai != null) sha256(File(ai.sourceDir)) else null,
                certSha1 = certSha1(pi),
                grantedPerms = granted,
                hasLauncher = pi.packageName in launchers,
                accessibility = pi.packageName in acc,
                deviceAdmin = pi.packageName in admins,
                notificationListener = pi.packageName in listeners,
                defaultSms = pi.packageName == sms,
                defaultHome = pi.packageName == home,
                overlayAllowed = ai != null && !system && overlayAllowed(ctx, ai, "android.permission.SYSTEM_ALERT_WINDOW" in requested),
            )
        }
    }
}
