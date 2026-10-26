package io.threatlens.core.update

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

data class UpdateInfo(
    val hasUpdate: Boolean,
    val latestVersion: String,
    val currentVersion: String = "1.0.0",
    val releaseUrl: String,
    val changelog: String? = null,
    val downloadApkUrl: String? = null
)

object UpdateCheckService {

    private val client = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .build()

    fun getInstalledVersionName(context: android.content.Context? = null): String {
        if (context == null) return "1.3.2"
        return try {
            val pInfo = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(context.packageName, android.content.pm.PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(context.packageName, 0)
            }
            pInfo.versionName ?: "1.3.2"
        } catch (_: Exception) {
            "1.3.2"
        }
    }

    suspend fun checkForUpdates(context: android.content.Context? = null): UpdateInfo = withContext(Dispatchers.IO) {
        val currentVer = getInstalledVersionName(context)
        try {
            val request = Request.Builder()
                .url("https://api.github.com/repos/sakinator/ThreatLens/releases/latest")
                .addHeader("User-Agent", "ThreatLens-Android-App")
                .addHeader("Accept", "application/vnd.github.v3+json")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    return@withContext UpdateInfo(
                        hasUpdate = false,
                        latestVersion = currentVer,
                        currentVersion = currentVer,
                        releaseUrl = "https://github.com/sakinator/ThreatLens/releases"
                    )
                }

                val raw = response.body?.string() ?: return@withContext UpdateInfo(false, currentVer, currentVer, "")
                val json = JSONObject(raw)

                val tagName = json.optString("tag_name", "").removePrefix("v").trim()
                val htmlUrl = json.optString("html_url", "https://github.com/sakinator/ThreatLens/releases")
                val body = json.optString("body", "Bug fixes and detection enhancements.")

                var apkDownloadUrl: String? = null
                val assets = json.optJSONArray("assets")
                if (assets != null && assets.length() > 0) {
                    for (i in 0 until assets.length()) {
                        val asset = assets.getJSONObject(i)
                        val name = asset.optString("name")
                        if (name.endsWith(".apk", ignoreCase = true)) {
                            apkDownloadUrl = asset.optString("browser_download_url")
                            break
                        }
                    }
                }

                val isNewer = isVersionGreater(tagName, currentVer)

                return@withContext UpdateInfo(
                    hasUpdate = isNewer,
                    latestVersion = tagName.ifBlank { currentVer },
                    currentVersion = currentVer,
                    releaseUrl = htmlUrl,
                    changelog = body,
                    downloadApkUrl = apkDownloadUrl
                )
            }
        } catch (_: Exception) {
            UpdateInfo(
                hasUpdate = false,
                latestVersion = currentVer,
                currentVersion = currentVer,
                releaseUrl = "https://github.com/sakinator/ThreatLens/releases"
            )
        }
    }

    private fun isVersionGreater(remote: String, local: String): Boolean {
        if (remote.isBlank() || local.isBlank()) return false
        try {
            val remoteParts = remote.split(".").mapNotNull { it.toIntOrNull() }
            val localParts = local.split(".").mapNotNull { it.toIntOrNull() }

            val maxLen = maxOf(remoteParts.size, localParts.size)
            for (i in 0 until maxLen) {
                val r = remoteParts.getOrElse(i) { 0 }
                val l = localParts.getOrElse(i) { 0 }
                if (r > l) return true
                if (r < l) return false
            }
        } catch (_: Exception) {}
        return false
    }
}
