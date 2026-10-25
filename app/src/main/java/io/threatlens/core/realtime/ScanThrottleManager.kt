package io.threatlens.core.realtime

import android.util.LruCache
import io.threatlens.core.model.ThreatReport

/**
 * High-efficiency cache & debounce manager.
 * Prevents redundant file scans, throttling duplicate events to preserve battery.
 */
object ScanThrottleManager {

    // Cache the last 500 scanned file hashes in memory
    private val memoryLruCache = LruCache<String, ThreatReport>(500)

    // Tracks recently processed file paths with timestamps to debounce rapid OS file events
    private val recentPathTimestamps = HashMap<String, Long>()

    @Synchronized
    fun shouldScanFile(filePath: String, extension: String): Boolean {
        val ext = extension.lowercase()

        // 1. Instant Extension Gatekeeper: Skip 99.9% of non-executable files
        if (ext !in ALLOWED_EXTENSIONS) {
            return false
        }

        // 2. Debounce: If the exact same path triggered in the last 3000ms, ignore
        val now = System.currentTimeMillis()
        val lastSeen = recentPathTimestamps[filePath] ?: 0L
        if (now - lastSeen < 3000L) {
            return false
        }
        recentPathTimestamps[filePath] = now

        // Clean up debounce map if it grows too large
        if (recentPathTimestamps.size > 200) {
            recentPathTimestamps.clear()
        }

        return true
    }

    @Synchronized
    fun getCachedReport(sha256: String): ThreatReport? {
        return memoryLruCache.get(sha256)
    }

    @Synchronized
    fun cacheReport(report: ThreatReport) {
        memoryLruCache.put(report.sha256, report)
    }

    private val ALLOWED_EXTENSIONS = setOf(
        "apk",
        "dex",
        "jar",
        "so",
        "bin"
    )
}
