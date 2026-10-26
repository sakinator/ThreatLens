package io.threatlens.core.diagnostics

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * High-precision human-friendly relative time formatter.
 *
 * Formats timestamps into readable relative tags:
 * "Updated just now", "Updated 14m ago", "Updated 5h ago", "Updated Yesterday", "Updated 3d ago".
 */
object RelativeTimeFormatter {

    fun format(timestamp: Long, currentTime: Long = System.currentTimeMillis()): String {
        if (timestamp <= 0L) return "Never updated"
        val diffMs = currentTime - timestamp
        if (diffMs < 0L) return "Updated just now"

        val diffSeconds = diffMs / 1000L
        val diffMinutes = diffSeconds / 60L
        val diffHours = diffMinutes / 60L
        val diffDays = diffHours / 24L

        return when {
            diffSeconds < 60L -> "Updated just now"
            diffMinutes < 60L -> "Updated ${diffMinutes}m ago"
            diffHours < 24L -> "Updated ${diffHours}h ago"
            diffDays == 1L -> "Updated Yesterday"
            diffDays < 7L -> "Updated ${diffDays}d ago"
            else -> {
                val sdf = SimpleDateFormat("MMM dd, yyyy", Locale.getDefault())
                "Updated ${sdf.format(Date(timestamp))}"
            }
        }
    }
}
