package de.svs.security.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import de.svs.security.scan.Severity

object Svs {
    val Red = Color(0xFFD0312D)
    val RedDark = Color(0xFFA5231F)
    val Green = Color(0xFF2E7D32)
    val Amber = Color(0xFFE08A00)
    val Blue = Color(0xFF1565C0)
    val Grey = Color(0xFF6B6B6B)

    fun color(s: Severity?) = when (s) {
        Severity.CRITICAL -> Color(0xFFB71C1C)
        Severity.HIGH -> Red
        Severity.MEDIUM -> Amber
        Severity.LOW -> Blue
        Severity.INFO, null -> Grey
    }
}

@Composable
fun SvsTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = if (dark) darkColorScheme(primary = Color(0xFFFF6B66), secondary = Color(0xFFFF8A80))
        else lightColorScheme(primary = Svs.Red, secondary = Svs.RedDark, primaryContainer = Color(0xFFFBE9E8)),
        content = content,
    )
}
