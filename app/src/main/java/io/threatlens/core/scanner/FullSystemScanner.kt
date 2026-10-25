package io.threatlens.core.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Environment
import io.threatlens.core.model.ThreatReport
import io.threatlens.core.model.ThreatSeverity
import io.threatlens.core.realtime.RealtimeScanCoordinator
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

enum class FullScanStatus {
    IDLE,
    SCANNING,
    PAUSED,
    COMPLETED,
    CANCELLED
}

data class FullScanState(
    val status: FullScanStatus = FullScanStatus.IDLE,
    val progress: Float = 0f,
    val scannedCount: Int = 0,
    val totalCount: Int = 0,
    val currentItemName: String = "",
    val threatsFound: List<ThreatReport> = emptyList(),
    val cleanCount: Int = 0,
    val durationMs: Long = 0L
)

object FullSystemScanner {

    private val scannerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var scanJob: Job? = null

    private val _scanState = MutableStateFlow(FullScanState())
    val scanState: StateFlow<FullScanState> = _scanState.asStateFlow()

    fun startFullScan(context: Context) {
        if (_scanState.value.status == FullScanStatus.SCANNING) return

        scanJob?.cancel()
        scanJob = scannerScope.launch {
            val startTime = System.currentTimeMillis()
            _scanState.value = FullScanState(status = FullScanStatus.SCANNING)

            val targets = collectAllTargets(context)
            val total = targets.size
            var scanned = 0
            var clean = 0
            val threats = mutableListOf<ThreatReport>()

            for (target in targets) {
                if (!isActive) {
                    _scanState.value = _scanState.value.copy(status = FullScanStatus.CANCELLED)
                    return@launch
                }

                // Check and handle paused state
                while (_scanState.value.status == FullScanStatus.PAUSED) {
                    if (!isActive) {
                        _scanState.value = _scanState.value.copy(status = FullScanStatus.CANCELLED)
                        return@launch
                    }
                    delay(150)
                }

                _scanState.value = _scanState.value.copy(
                    progress = if (total > 0) scanned.toFloat() / total.toFloat() else 0f,
                    scannedCount = scanned,
                    totalCount = total,
                    currentItemName = target.name,
                    threatsFound = threats.toList(),
                    cleanCount = clean
                )

                try {
                    val report = RealtimeScanCoordinator.performScan(
                        context = context,
                        file = target.file,
                        customAppName = target.name,
                        customPackageName = target.packageName
                    )
                    if (report.severity == ThreatSeverity.MALICIOUS || report.severity == ThreatSeverity.HIGH_RISK || report.severity == ThreatSeverity.SUSPICIOUS) {
                        threats.add(report)
                    } else {
                        clean++
                    }
                } catch (_: Exception) {}

                scanned++
                // Brief cooperative yield to keep UI responsive
                delay(15)
            }

            val elapsed = System.currentTimeMillis() - startTime
            _scanState.value = FullScanState(
                status = FullScanStatus.COMPLETED,
                progress = 1.0f,
                scannedCount = scanned,
                totalCount = total,
                currentItemName = "Scan Complete",
                threatsFound = threats,
                cleanCount = clean,
                durationMs = elapsed
            )
        }
    }

    fun pauseScan() {
        if (_scanState.value.status == FullScanStatus.SCANNING) {
            _scanState.value = _scanState.value.copy(status = FullScanStatus.PAUSED)
        }
    }

    fun resumeScan() {
        if (_scanState.value.status == FullScanStatus.PAUSED) {
            _scanState.value = _scanState.value.copy(status = FullScanStatus.SCANNING)
        }
    }

    fun abortScan() {
        scanJob?.cancel()
        _scanState.value = _scanState.value.copy(status = FullScanStatus.CANCELLED)
    }

    fun cancelScan() {
        abortScan()
    }

    private fun collectAllTargets(context: Context): List<ScanItem> {
        val list = mutableListOf<ScanItem>()
        val pm = context.packageManager

        // 1. Installed Applications
        try {
            val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            for (app in installedApps) {
                // Filter out system apps unless they are third-party or updated
                val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

                if (!isSystem || isUpdatedSystem) {
                    if (io.threatlens.core.exclusions.ExclusionManager.isPackageExcluded(app.packageName)) {
                        continue
                    }
                    val apkFile = File(app.publicSourceDir)
                    if (apkFile.exists() && !io.threatlens.core.exclusions.ExclusionManager.isPathExcluded(apkFile.absolutePath)) {
                        val appName = pm.getApplicationLabel(app).toString()
                        list.add(ScanItem(appName, apkFile, app.packageName))
                    }
                }
            }
        } catch (_: Exception) {}

        // 2. Downloaded APKs & Executables in /Downloads
        try {
            val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (downloads.exists() && downloads.isDirectory) {
                downloads.listFiles { f ->
                    val ext = f.extension.lowercase()
                    ext in listOf("apk", "dex", "jar", "bin")
                }?.forEach { f ->
                    var dlAppName = f.name
                    var dlPkgName: String? = null
                    if (f.extension.equals("apk", ignoreCase = true)) {
                        try {
                            val pi = pm.getPackageArchiveInfo(f.absolutePath, 0)
                            if (pi != null) {
                                dlPkgName = pi.packageName
                                pi.applicationInfo.sourceDir = f.absolutePath
                                pi.applicationInfo.publicSourceDir = f.absolutePath
                                val lbl = pm.getApplicationLabel(pi.applicationInfo).toString()
                                if (lbl.isNotBlank()) dlAppName = lbl
                            }
                        } catch (_: Exception) {}
                    }
                    list.add(ScanItem(dlAppName, f, dlPkgName))
                }
            }
        } catch (_: Exception) {}

        return list.distinctBy { it.file.absolutePath }
    }

    private data class ScanItem(val name: String, val file: File, val packageName: String? = null)
}
