package de.svs.security.ui

import android.content.Intent
import android.widget.Toast
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import de.svs.security.Actions

/** Vollbild-Ansicht der Gesamtuebersicht mit Kopieren, Teilen und Speichern. */
@Composable
fun ReportDialog(vm: AppViewModel, save: () -> Unit) {
    val text by vm.report.collectAsState()
    val report = text ?: return
    val ctx = LocalContext.current
    Dialog(onDismissRequest = { vm.closeReport() }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("Gesamtübersicht", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = Brand.Primary)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        Actions.copy(ctx, report)
                        Toast.makeText(ctx, "In die Zwischenablage kopiert", Toast.LENGTH_SHORT).show()
                    }) { Text("Kopieren") }
                    OutlinedButton(onClick = {
                        ctx.startActivity(Intent.createChooser(
                            Intent(Intent.ACTION_SEND).setType("text/plain")
                                .putExtra(Intent.EXTRA_SUBJECT, "Handywächter – Gesamtübersicht")
                                .putExtra(Intent.EXTRA_TEXT, report), "Bericht teilen"))
                    }) { Text("Teilen") }
                    OutlinedButton(onClick = save) { Text("Speichern") }
                }
                Surface(Modifier.weight(1f).fillMaxWidth(), color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f), shape = MaterialTheme.shapes.medium) {
                    SelectionContainer {
                        Text(
                            report, fontFamily = FontFamily.Monospace, fontSize = 11.sp, lineHeight = 15.sp,
                            modifier = Modifier.verticalScroll(rememberScrollState()).horizontalScroll(rememberScrollState()).padding(12.dp),
                        )
                    }
                }
                TextButton(onClick = { vm.closeReport() }, modifier = Modifier.fillMaxWidth()) { Text("Schließen") }
            }
        }
    }
}
