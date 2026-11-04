package io.threatlens.core.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import io.threatlens.core.diagnostics.AppDiagnosticLogger
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
    val durationMs: Long = 0L,
    val allScannedReports: List<ThreatReport> = emptyList()
)

object FullSystemScanner {

    private val scannerScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var scanJob: Job? = null

    private val _scanState = MutableStateFlow(FullScanState())
    val scanState: StateFlow<FullScanState> = _scanState.asStateFlow()

    fun startFullScan(context: Context) {
        if (_scanState.value.status == FullScanStatus.SCANNING) return
        _scanState.value = FullScanState(
            status = FullScanStatus.SCANNING,
            currentItemName = "Enumerating installed applications & targets..."
        )
        scanJob?.cancel()
        scanJob = scannerScope.launch {
            val targets = collectAllTargets(context)
            if (!isActive) return@launch
            if (targets.isEmpty()) {
                _scanState.value = FullScanState(
                    status = FullScanStatus.COMPLETED,
                    currentItemName = "No applications or targets found"
                )
                return@launch
            }
            executeScanPipeline(context, targets)
        }
    }

    fun startSelectedAppsScan(context: Context, packageNames: List<String>) {
        if (_scanState.value.status == FullScanStatus.SCANNING || packageNames.isEmpty()) return
        _scanState.value = FullScanState(
            status = FullScanStatus.SCANNING,
            currentItemName = "Preparing selected applications..."
        )
        scanJob?.cancel()
        scanJob = scannerScope.launch {
            val pm = context.packageManager
            val targets = mutableListOf<ScanItem>()

            for (pkg in packageNames) {
                if (!isActive) return@launch
                try {
                    val pInfo = try { pm.getPackageInfo(pkg, 0) } catch (_: Exception) { null }
                    val app = pInfo?.applicationInfo
                    val publicDir = app?.publicSourceDir
                    if (app != null && publicDir != null) {
                        val apkFile = File(publicDir)
                        if (apkFile.exists()) {
                            val appName = try { pm.getApplicationLabel(app).toString() } catch (_: Exception) { pkg }
                            val vCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pInfo.longVersionCode else @Suppress("DEPRECATION") (pInfo.versionCode.toLong())
                            val uTime = pInfo.lastUpdateTime
                            targets.add(ScanItem(appName, apkFile, pkg, vCode, uTime))
                        }
                    }
                } catch (_: Exception) {}
            }
            if (!isActive) return@launch
            if (targets.isEmpty()) {
                _scanState.value = FullScanState(
                    status = FullScanStatus.COMPLETED,
                    currentItemName = "No valid applications found"
                )
                return@launch
            }
            executeScanPipeline(context, targets)
        }
    }

    fun startFolderScan(context: Context, treeUri: Uri) {
        if (_scanState.value.status == FullScanStatus.SCANNING) return
        _scanState.value = FullScanState(
            status = FullScanStatus.SCANNING,
            currentItemName = "Enumerating folder targets..."
        )
        scanJob?.cancel()
        scanJob = scannerScope.launch {
            val targets = collectFolderTargets(context, treeUri)
            if (!isActive) return@launch
            if (targets.isEmpty()) {
                _scanState.value = FullScanState(
                    status = FullScanStatus.COMPLETED,
                    currentItemName = "No executable files found in folder"
                )
                return@launch
            }
            executeScanPipeline(context, targets)
        }
    }

    fun startSingleFileScan(context: Context, file: File, displayName: String? = null) {
        if (!file.exists()) return
        val name = displayName ?: file.name
        val targets = listOf(ScanItem(name, file, null, 0L, 0L))
        _scanState.value = FullScanState(
            status = FullScanStatus.SCANNING,
            currentItemName = "Preparing single file scan..."
        )
        scanJob?.cancel()
        scanJob = scannerScope.launch {
            executeScanPipeline(context, targets)
        }
    }

    private suspend fun executeScanPipeline(context: Context, targets: List<ScanItem>) {
        try {
            val startTime = System.currentTimeMillis()
            val total = targets.size
            var scanned = 0
            var clean = 0
            val threats = mutableListOf<ThreatReport>()
            val allReports = mutableListOf<ThreatReport>()

            _scanState.value = FullScanState(
                status = FullScanStatus.SCANNING,
                totalCount = total,
                scannedCount = 0,
                progress = 0f,
                currentItemName = if (targets.isNotEmpty()) targets[0].name else "Initializing scan..."
            )

            for (target in targets) {
                if (!coroutineContext.isActive) {
                    _scanState.value = _scanState.value.copy(status = FullScanStatus.CANCELLED)
                    return
                }

                // Check and handle paused state
                while (_scanState.value.status == FullScanStatus.PAUSED) {
                    if (!coroutineContext.isActive) {
                        _scanState.value = _scanState.value.copy(status = FullScanStatus.CANCELLED)
                        return
                    }
                    delay(150)
                }

                // 1. Fast Cache Check: If already verified clean and un-updated, instant skip deep parsing
                if (target.packageName != null && target.lastUpdateTime > 0L) {
                    val cached = ScanCacheManager.getCachedVerdict(context, target.packageName, target.versionCode, target.lastUpdateTime)
                    if (cached != null) {
                        clean++
                        scanned++
                        val cachedReport = ThreatReport(
                            targetName = target.file.name,
                            targetPath = target.file.absolutePath,
                            appName = target.name,
                            packageName = target.packageName,
                            sha256 = "",
                            fileSize = target.file.length(),
                            isApk = true,
                            localScore = 0,
                            cloudScore = 0,
                            currentScore = 0,
                            severity = ThreatSeverity.SAFE,
                            threatFamily = "Clean",
                            detectionType = io.threatlens.core.model.DetectionType.CLEAN,
                            engineVerdictMap = mapOf(
                                "ThreatLens Local Engine" to "Clean (Cached Safe)",
                                "ThreatLens Offline Signature DB" to "Clean (${io.threatlens.core.local.LocalSignatureDatabase.totalSignatures} definitions checked)"
                            )
                        )
                        allReports.add(cachedReport)
                        _scanState.value = _scanState.value.copy(
                            progress = if (total > 0) scanned.toFloat() / total.toFloat() else 0f,
                            scannedCount = scanned,
                            totalCount = total,
                            currentItemName = target.name,
                            cleanCount = clean,
                            threatsFound = threats.toList(),
                            allScannedReports = allReports.toList()
                        )
                        delay(10) // Brief yield for UI looper
                        continue
                    }
                }

                try {
                    val report = RealtimeScanCoordinator.performScan(
                        context = context,
                        file = target.file,
                        customAppName = target.name,
                        customPackageName = target.packageName,
                        isFullScan = true,
                        totalScanCount = targets.size
                    )
                    allReports.add(report)
                    if (report.severity == ThreatSeverity.MALICIOUS || report.severity == ThreatSeverity.HIGH_RISK || report.severity == ThreatSeverity.SUSPICIOUS) {
                        threats.add(report)
                    } else {
                        clean++
                        if (target.packageName != null && target.lastUpdateTime > 0L) {
                            ScanCacheManager.putCachedVerdict(
                                context,
                                target.packageName,
                                target.versionCode,
                                target.lastUpdateTime,
                                io.threatlens.core.local.LocalAntivirusEngine.LocalScanVerdict(
                                    isMalicious = false,
                                    localScore = report.currentScore,
                                    threatFamily = report.threatFamily,
                                    category = "Clean",
                                    detectedBehaviors = emptyList(),
                                    dangerousPermissions = emptyList(),
                                    matchedSignatures = emptyList(),
                                    engineSources = listOf("ThreatLens Local Engine (Cached Safe)")
                                )
                            )
                        }
                    }
                } catch (_: Exception) {}

                scanned++
                _scanState.value = _scanState.value.copy(
                    progress = if (total > 0) scanned.toFloat() / total.toFloat() else 0f,
                    scannedCount = scanned,
                    totalCount = total,
                    currentItemName = target.name,
                    cleanCount = clean,
                    threatsFound = threats.toList(),
                    allScannedReports = allReports.toList()
                )
                // Brief cooperative yield to keep UI responsive
                delay(20)
            }

            val elapsed = System.currentTimeMillis() - startTime
            val completedState = FullScanState(
                status = FullScanStatus.COMPLETED,
                progress = 1.0f,
                scannedCount = scanned,
                totalCount = total,
                currentItemName = "Scan Complete",
                threatsFound = threats,
                cleanCount = clean,
                durationMs = elapsed,
                allScannedReports = allReports.toList()
            )
            _scanState.value = completedState

            // Persist all scanned reports to disk so results survive reboots and app restarts
            if (allReports.isNotEmpty()) {
                ScanReportRepository.saveReports(context, allReports)
            }
        } catch (_: kotlinx.coroutines.CancellationException) {
            _scanState.value = _scanState.value.copy(status = FullScanStatus.CANCELLED)
        } catch (e: Exception) {
            AppDiagnosticLogger.log("FullSystemScanner", "Scan error: ${e.message}")
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

        // 1. Installed Applications (High-speed batch retrieval via getInstalledPackages to prevent Binder IPC ANR)
        try {
            val installedPackages = pm.getInstalledPackages(0)
            for (pInfo in installedPackages) {
                val app = pInfo.applicationInfo ?: continue
                val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

                if (!isSystem || isUpdatedSystem) {
                    val pkgName = pInfo.packageName
                    if (io.threatlens.core.exclusions.ExclusionManager.isPackageExcluded(pkgName)) {
                        continue
                    }
                    val publicDir = app.publicSourceDir ?: continue
                    val apkFile = File(publicDir)
                    if (apkFile.exists() && !io.threatlens.core.exclusions.ExclusionManager.isPathExcluded(apkFile.absolutePath)) {
                        val appName = try { pm.getApplicationLabel(app).toString() } catch (_: Exception) { pkgName }
                        val vCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pInfo.longVersionCode else @Suppress("DEPRECATION") (pInfo.versionCode.toLong())
                        val uTime = pInfo.lastUpdateTime
                        list.add(ScanItem(appName, apkFile, pkgName, vCode, uTime))
                    }
                }
            }
        } catch (_: Exception) {
            // Fallback to getInstalledApplications
            try {
                val installedApps = pm.getInstalledApplications(0)
                for (app in installedApps) {
                    val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                    val isUpdatedSystem = (app.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

                    if (!isSystem || isUpdatedSystem) {
                        if (io.threatlens.core.exclusions.ExclusionManager.isPackageExcluded(app.packageName)) {
                            continue
                        }
                        val publicDir = app.publicSourceDir ?: continue
                        val apkFile = File(publicDir)
                        if (apkFile.exists() && !io.threatlens.core.exclusions.ExclusionManager.isPathExcluded(apkFile.absolutePath)) {
                            val appName = pm.getApplicationLabel(app).toString()
                            val pInfo = try { pm.getPackageInfo(app.packageName, 0) } catch (_: Exception) { null }
                            val vCode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pInfo?.longVersionCode ?: 0L else @Suppress("DEPRECATION") (pInfo?.versionCode?.toLong() ?: 0L)
                            val uTime = pInfo?.lastUpdateTime ?: 0L
                            list.add(ScanItem(appName, apkFile, app.packageName, vCode, uTime))
                        }
                    }
                }
            } catch (_: Exception) {}
        }

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

    private fun collectFolderTargets(context: Context, treeUri: Uri): List<ScanItem> {
        val list = mutableListOf<ScanItem>()
        val pm = context.packageManager
        val contentResolver = context.contentResolver
        val targetExtensions = setOf("apk", "dex", "jar", "so", "bin")
        val cacheFolder = File(context.cacheDir, "folder_scan_temp").apply { mkdirs() }

        try {
            val treeDocumentId = if (DocumentsContract.isDocumentUri(context, treeUri)) {
                DocumentsContract.getDocumentId(treeUri)
            } else {
                DocumentsContract.getTreeDocumentId(treeUri)
            }
            val rootChildrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeDocumentId)
            val queue = ArrayDeque<Uri>()
            queue.add(rootChildrenUri)

            while (queue.isNotEmpty() && list.size < 300) {
                val currentUri = queue.removeFirst()
                try {
                    contentResolver.query(
                        currentUri,
                        arrayOf(
                            DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                            DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                            DocumentsContract.Document.COLUMN_MIME_TYPE
                        ),
                        null, null, null
                    )?.use { cursor ->
                        val idIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                        val nameIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                        val mimeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)

                        while (cursor.moveToNext() && list.size < 300) {
                            val docId = cursor.getString(idIdx) ?: continue
                            val name = cursor.getString(nameIdx) ?: "file"
                            val mime = cursor.getString(mimeIdx) ?: ""

                            if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                                val childDirUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, docId)
                                queue.add(childDirUri)
                            } else {
                                val ext = name.substringAfterLast('.', "").lowercase()
                                if (ext in targetExtensions) {
                                    val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                                    val tempFile = File(cacheFolder, "${System.currentTimeMillis()}_$name")
                                    contentResolver.openInputStream(docUri)?.use { input ->
                                        tempFile.outputStream().use { output -> input.copyTo(output) }
                                    }
                                    if (tempFile.exists() && tempFile.length() > 0) {
                                        var pkgName: String? = null
                                        var appName = name
                                        if (ext == "apk") {
                                            try {
                                                val pi = pm.getPackageArchiveInfo(tempFile.absolutePath, 0)
                                                if (pi != null) {
                                                    pkgName = pi.packageName
                                                    pi.applicationInfo.sourceDir = tempFile.absolutePath
                                                    pi.applicationInfo.publicSourceDir = tempFile.absolutePath
                                                    val lbl = pm.getApplicationLabel(pi.applicationInfo).toString()
                                                    if (lbl.isNotBlank()) appName = lbl
                                                }
                                            } catch (_: Exception) {}
                                        }
                                        list.add(ScanItem(appName, tempFile, pkgName))
                                    }
                                }
                            }
                        }
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}

        return list
    }

    private data class ScanItem(
        val name: String,
        val file: File,
        val packageName: String? = null,
        val versionCode: Long = 0L,
        val lastUpdateTime: Long = 0L
    )
}
