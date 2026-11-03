package de.svs.security

import android.Manifest
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Help
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import de.svs.security.ui.AppViewModel
import de.svs.security.ui.DataScreen
import de.svs.security.ui.HelpScreen
import de.svs.security.ui.HistoryScreen
import de.svs.security.ui.ProtectScreen
import de.svs.security.ui.ReportDialog
import de.svs.security.ui.ScanScreen
import de.svs.security.ui.Svs
import de.svs.security.ui.SvsTheme
import de.svs.security.vpn.WebShieldService

enum class Tab(val key: String, val label: String, val icon: ImageVector) {
    SCAN("scan", "Prüfen", Icons.Filled.Security),
    HISTORY("history", "Verlauf", Icons.Filled.History),
    PROTECT("protect", "Schutz", Icons.Filled.Shield),
    DATA("data", "Daten", Icons.Filled.Public),
    HELP("help", "Hilfe", Icons.Filled.Help),
}

class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()
    private val tab = mutableStateOf(Tab.SCAN)
    private val sharedText = mutableStateOf<String?>(null)

    private val saveReport = registerForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        val text = vm.report.value ?: return@registerForActivityResult
        if (uri == null) return@registerForActivityResult
        val ok = runCatching { contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray(Charsets.UTF_8)) } != null }.getOrDefault(false)
        android.widget.Toast.makeText(this, if (ok) "Bericht gespeichert" else "Speichern fehlgeschlagen", android.widget.Toast.LENGTH_SHORT).show()
    }

    private val notifPerm = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (android.net.VpnService.prepare(this) == null) WebShieldService.start(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        handle(intent)
        if (Build.VERSION.SDK_INT >= 33) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
        setContent { SvsTheme { Root() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handle(intent)
    }

    private fun handle(i: Intent?) {
        i ?: return
        Tab.entries.firstOrNull { it.key == i.getStringExtra("tab") }?.let { tab.value = it }
        if (i.action == Intent.ACTION_SEND) {
            sharedText.value = i.getStringExtra(Intent.EXTRA_TEXT)
            tab.value = Tab.PROTECT
        }
    }

    fun saveReportFile() = saveReport.launch(de.svs.security.report.ReportFormatter.fileName(vm.reportCreated))

    fun enableShield() {
        val consent = android.net.VpnService.prepare(this)
        if (consent != null) vpnConsent.launch(consent) else WebShieldService.start(this)
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun Root() {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = { Text("SVS Security · ${tab.value.label}") },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = Svs.Red, titleContentColor = Color.White),
                )
            },
            bottomBar = {
                NavigationBar {
                    Tab.entries.forEach { t ->
                        NavigationBarItem(
                            selected = tab.value == t, onClick = { tab.value = t },
                            icon = { Icon(t.icon, null) }, label = { Text(t.label) },
                        )
                    }
                }
            },
        ) { pad ->
            val m = Modifier.padding(pad)
            ReportDialog(vm, ::saveReportFile)
            when (tab.value) {
                Tab.SCAN -> ScanScreen(vm, m) { tab.value = it }
                Tab.HISTORY -> HistoryScreen(vm, m)
                Tab.PROTECT -> ProtectScreen(vm, m, sharedText.value, ::enableShield) { sharedText.value = null }
                Tab.DATA -> DataScreen(vm, m)
                Tab.HELP -> HelpScreen(vm, m)
            }
        }
    }
}
