package io.threatlens.core.diagnostics

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * ThreatLens In-App Diagnostic Error Log Manager.
 *
 * Captures errors, scan failures, timeouts, and system telemetry in a ring buffer
 * and local log file with full privacy redaction (stripping user tokens/keys).
 */
object AppDiagnosticLogger {

    private const val MAX_MEMORY_LOGS = 250
    private const val LOG_FILE_NAME = "threatlens_diagnostics.log"
    private val memoryLog = ConcurrentLinkedQueue<String>()
    private val timeFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)

    fun log(tag: String, message: String) {
        val sanitized = sanitize(message)
        val entry = "[${timeFormat.format(Date())}] [INFO] [$tag] $sanitized"
        appendLog(entry)
    }

    fun logError(tag: String, message: String, throwable: Throwable? = null) {
        val sanitized = sanitize(message)
        val stackTrace = throwable?.let {
            val sw = StringWriter()
            it.printStackTrace(PrintWriter(sw))
            "\n" + sanitize(sw.toString())
        } ?: ""
        val entry = "[${timeFormat.format(Date())}] [ERROR] [$tag] $sanitized$stackTrace"
        appendLog(entry)
    }

    private fun appendLog(entry: String) {
        memoryLog.add(entry)
        while (memoryLog.size > MAX_MEMORY_LOGS) {
            memoryLog.poll()
        }
    }

    fun getLogsAsText(context: Context): String {
        val sb = StringBuilder()
        sb.appendLine("=================================================================")
        sb.appendLine("       THREATLENS DIAGNOSTIC ERROR & TELEMETRY LOG REPORT       ")
        sb.appendLine("=================================================================")
        sb.appendLine("Generated At: ${timeFormat.format(Date())}")
        sb.appendLine("Device Model: ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})")
        sb.appendLine("Android OS: Version ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})")
        sb.appendLine("CPU ABI: ${Build.SUPPORTED_ABIS.joinToString(", ")}")
        sb.appendLine("Package: ${context.packageName}")
        sb.appendLine("=================================================================\n")

        if (memoryLog.isEmpty()) {
            sb.appendLine("No application errors or diagnostic anomalies recorded.")
        } else {
            memoryLog.forEach { sb.appendLine(it) }
        }

        return sb.toString()
    }

    fun copyLogsToClipboard(context: Context) {
        val logContent = getLogsAsText(context)
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("ThreatLens Diagnostics", logContent)
        clipboard.setPrimaryClip(clip)
        Toast.makeText(context, "✓ Diagnostic log copied to clipboard!", Toast.LENGTH_SHORT).show()
    }

    fun shareLogFile(context: Context) {
        try {
            val logContent = getLogsAsText(context)
            val cacheFile = File(context.cacheDir, LOG_FILE_NAME)
            cacheFile.writeText(logContent)

            val uri = FileProvider.getUriForFile(
                context,
                "${context.packageName}.fileprovider",
                cacheFile
            )

            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                putExtra(Intent.EXTRA_SUBJECT, "ThreatLens Diagnostic Error Log")
                putExtra(Intent.EXTRA_TEXT, "ThreatLens diagnostic error log attached for troubleshooting.")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }

            context.startActivity(Intent.createChooser(shareIntent, "Share ThreatLens Diagnostic Log").apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            })
        } catch (e: Exception) {
            logError("DiagnosticLogger", "Failed to share diagnostic log file", e)
            Toast.makeText(context, "Failed to share log: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Strips API keys, auth headers, and tokens from logs for user privacy.
     */
    fun sanitize(raw: String): String {
        return raw
            .replace(Regex("""(?i)(key|token|auth|secret|bearer)\s*[:=]\s*[a-zA-Z0-9_\-]{16,}"""), "$1=[REDACTED]")
            .replace(Regex("""AIza[0-9A-Za-z\-_]{35}"""), "AIza[REDACTED]")
            .replace(Regex("""x-api-key:\s*[^\s]+"""), "x-api-key: [REDACTED]")
    }
}
