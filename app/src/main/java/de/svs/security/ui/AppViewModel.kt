package de.svs.security.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import de.svs.security.history.LogEvent
import de.svs.security.history.Timeline
import de.svs.security.intel.ThreatDb
import de.svs.security.intel.ThreatIntel
import de.svs.security.monitor.Monitor
import de.svs.security.report.ReportBuilder
import de.svs.security.scan.ScanResult
import de.svs.security.scan.Scanner
import de.svs.security.update.ReleaseInfo
import de.svs.security.update.UpdateChecker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val ctx get() = getApplication<Application>()

    val scan = MutableStateFlow<ScanResult?>(Scanner.last(app))
    val scanProgress = MutableStateFlow<Pair<String, Float>?>(null)

    val timeline = MutableStateFlow<List<LogEvent>>(emptyList())
    val timelineLoading = MutableStateFlow(false)
    val timelineDays = MutableStateFlow(2)

    val intelUpdating = MutableStateFlow(false)
    val intelMessage = MutableStateFlow<String?>(null)

    val update = MutableStateFlow<ReleaseInfo?>(null)
    val updateStatus = MutableStateFlow<String?>(null)
    val updateBusy = MutableStateFlow(false)

    val linkResult = MutableStateFlow<Pair<String, String?>?>(null)

    /** Gesamtuebersicht (Text) – null = nicht geoeffnet */
    val report = MutableStateFlow<String?>(null)
    val reportBusy = MutableStateFlow(false)
    var reportCreated = 0L
        private set

    init {
        viewModelScope.launch(Dispatchers.Default) { runCatching { Monitor.check(ctx) } }
        // Beim ersten Start sofort aktuelle Bedrohungsdaten holen
        if (ThreatIntel.status.value.lastUpdate == 0L && ctx.getSharedPreferences("intel", 0).getLong("last", 0L) == 0L) updateIntel()
    }

    fun startScan() {
        if (scanProgress.value != null) return
        viewModelScope.launch {
            scanProgress.value = "Starte …" to 0f
            if (ThreatIntel.db.domainCount == 0) ThreatIntel.load(ctx)
            val r = runCatching { Scanner.run(ctx) { s, p -> scanProgress.value = s to p } }.getOrNull()
            if (r != null) scan.value = r
            scanProgress.value = null
        }
    }

    fun buildReport() {
        if (reportBusy.value) return
        viewModelScope.launch {
            reportBusy.value = true
            reportCreated = System.currentTimeMillis()
            report.value = runCatching { ReportBuilder.build(ctx) }.getOrElse { "Bericht konnte nicht erstellt werden: ${it.message}" }
            reportBusy.value = false
        }
    }

    fun closeReport() { report.value = null }

    fun loadTimeline(days: Int = timelineDays.value) {
        timelineDays.value = days
        viewModelScope.launch {
            timelineLoading.value = true
            val to = System.currentTimeMillis()
            val from = startOfDay(to) - (days - 1) * 86_400_000L
            timeline.value = withContext(Dispatchers.Default) { runCatching { Timeline.build(ctx, from, to) }.getOrDefault(emptyList()) }
            timelineLoading.value = false
        }
    }

    fun updateIntel() {
        if (intelUpdating.value) return
        viewModelScope.launch {
            intelUpdating.value = true
            intelMessage.value = "Lade aktuelle Bedrohungsdaten …"
            val n = runCatching { ThreatIntel.update(ctx) }.getOrDefault(0)
            intelMessage.value = if (n == ThreatIntel.SOURCES.size) "Alle ${ThreatIntel.SOURCES.size} Quellen aktualisiert"
            else "$n von ${ThreatIntel.SOURCES.size} Quellen aktualisiert – Rest beim nächsten Mal"
            intelUpdating.value = false
        }
    }

    fun checkLink(input: String) {
        val host = ThreatDb.hostOf(input)
        if (host == null) { linkResult.value = input to "Kein gültiger Link erkannt"; return }
        viewModelScope.launch {
            if (ThreatIntel.db.domainCount == 0) ThreatIntel.load(ctx)
            linkResult.value = host to ThreatIntel.db.domainThreat(host)
        }
    }

    fun checkUpdate(install: Boolean = false) {
        if (updateBusy.value) return
        viewModelScope.launch {
            updateBusy.value = true
            updateStatus.value = "Suche nach Updates …"
            runCatching { UpdateChecker.latest() }
                .onSuccess { r ->
                    val cur = UpdateChecker.currentBuild(ctx)
                    if (r.build > cur && r.apkUrl != null) {
                        update.value = r
                        updateStatus.value = "Neue Version verfügbar: ${r.title}"
                        if (install) downloadAndInstall()
                    } else {
                        update.value = null
                        updateStatus.value = "Du hast die neueste Version (${UpdateChecker.currentVersion(ctx)})"
                    }
                }
                .onFailure { updateStatus.value = it.message ?: "Update-Prüfung fehlgeschlagen" }
            updateBusy.value = false
        }
    }

    fun downloadAndInstall() {
        val r = update.value ?: return
        if (!UpdateChecker.canInstall(ctx)) {
            UpdateChecker.openInstallPermission(ctx)
            updateStatus.value = "Bitte „Unbekannte Apps installieren“ für SVS Security erlauben und erneut tippen"
            return
        }
        viewModelScope.launch {
            updateBusy.value = true
            updateStatus.value = "Lade ${r.title} …"
            runCatching { UpdateChecker.download(ctx, r) }
                .onSuccess { updateStatus.value = "Installation wird geöffnet …"; UpdateChecker.install(ctx, it) }
                .onFailure { updateStatus.value = it.message ?: "Download fehlgeschlagen" }
            updateBusy.value = false
        }
    }

    companion object {
        fun startOfDay(t: Long): Long {
            val c = java.util.Calendar.getInstance().apply {
                timeInMillis = t
                set(java.util.Calendar.HOUR_OF_DAY, 0); set(java.util.Calendar.MINUTE, 0)
                set(java.util.Calendar.SECOND, 0); set(java.util.Calendar.MILLISECOND, 0)
            }
            return c.timeInMillis
        }
    }
}
