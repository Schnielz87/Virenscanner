package de.svs.security

import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.widget.Toast
import de.svs.security.scan.FixAction

/** Oeffnet die passenden Android-Einstellungen zu einem Befund. */
object Actions {

    fun run(ctx: Context, action: FixAction, pkg: String?) {
        when (action) {
            FixAction.NONE -> Unit
            FixAction.APP_SETTINGS -> appSettings(ctx, pkg)
            FixAction.UNINSTALL -> pkg?.let { uninstall(ctx, it) }
            FixAction.ACCESSIBILITY -> open(ctx, Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
            FixAction.DEVICE_ADMIN -> open(ctx, Intent().setClassName("com.android.settings", "com.android.settings.DeviceAdminSettings"),
                Intent(Settings.ACTION_SECURITY_SETTINGS))
            FixAction.NOTIFICATION_ACCESS -> open(ctx, Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
            FixAction.SECURITY_SETTINGS -> open(ctx, Intent(Settings.ACTION_SECURITY_SETTINGS))
            FixAction.DEV_SETTINGS -> open(ctx, Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))
            FixAction.PRIVATE_DNS -> privateDns(ctx)
            FixAction.HOME_SETTINGS -> open(ctx, Intent(Settings.ACTION_HOME_SETTINGS), Intent(Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS))
            FixAction.UPDATE_SETTINGS -> open(ctx, Intent("android.settings.SYSTEM_UPDATE_SETTINGS"), Intent(Settings.ACTION_DEVICE_INFO_SETTINGS))
        }
    }

    fun appSettings(ctx: Context, pkg: String?) = open(
        ctx,
        if (pkg != null) Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg"))
        else Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS),
    )

    fun uninstall(ctx: Context, pkg: String) {
        @Suppress("DEPRECATION")
        open(ctx, Intent(Intent.ACTION_UNINSTALL_PACKAGE, Uri.parse("package:$pkg")), Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
    }

    /** Privates DNS: Hostname kopieren und Netzwerkeinstellungen oeffnen. */
    fun privateDns(ctx: Context) {
        copy(ctx, "dns.quad9.net")
        Toast.makeText(ctx, "„dns.quad9.net“ kopiert – unter „Privates DNS“ → „Hostname des privaten DNS-Anbieters“ einfügen", Toast.LENGTH_LONG).show()
        open(ctx, Intent("android.settings.PRIVATE_DNS_SETTINGS"), Intent(Settings.ACTION_WIRELESS_SETTINGS), Intent(Settings.ACTION_SETTINGS))
    }

    fun usageAccess(ctx: Context) = open(ctx, Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS, Uri.parse("package:${ctx.packageName}")),
        Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))

    fun vpnSettings(ctx: Context) = open(ctx, Intent(Settings.ACTION_VPN_SETTINGS))
    fun backupSettings(ctx: Context) = open(ctx, Intent("android.settings.PRIVACY_SETTINGS"), Intent(Settings.ACTION_SETTINGS))

    fun url(ctx: Context, url: String) = open(ctx, Intent(Intent.ACTION_VIEW, Uri.parse(url)))

    fun call(ctx: Context, number: String) = open(ctx, Intent(Intent.ACTION_DIAL, Uri.parse("tel:$number")))

    fun copy(ctx: Context, text: String) {
        (ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("Handywächter", text))
    }

    /** Erstes Intent, das funktioniert. */
    fun open(ctx: Context, vararg intents: Intent) {
        for (i in intents) {
            try {
                ctx.startActivity(i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)); return
            } catch (_: ActivityNotFoundException) {
            } catch (_: SecurityException) {
            }
        }
        Toast.makeText(ctx, "Diese Einstellung konnte nicht geöffnet werden", Toast.LENGTH_SHORT).show()
    }
}
