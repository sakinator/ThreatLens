package io.threatlens.core.local

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

/**
 * ThreatLens User Whitelist & Trust Manager.
 *
 * Allows users to mark legitimate developer tools, internal corporate applications,
 * or open-source packages as trusted to suppress heuristic alerts and false alarms.
 */
object ThreatWhitelistManager {

    private const val PREFS_NAME = "threatlens_whitelist_prefs"
    private const val KEY_WHITELISTED_JSON = "whitelisted_packages_json"

    data class WhitelistedApp(
        val packageName: String,
        val appName: String,
        val sha256: String,
        val addedTimestamp: Long
    )

    private var cachedWhitelistedApps: List<WhitelistedApp>? = null
    private val whitelistLock = Any()

    private fun getPrefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    /**
     * Checks if a package or SHA256 hash has been whitelisted by the user.
     */
    fun isWhitelisted(context: Context, packageName: String?, sha256: String?): Boolean {
        if (packageName.isNullOrBlank() && sha256.isNullOrBlank()) return false
        val list = getWhitelistedApps(context)
        return list.any { app ->
            (!packageName.isNullOrBlank() && app.packageName.equals(packageName.trim(), ignoreCase = true)) ||
            (!sha256.isNullOrBlank() && app.sha256.equals(sha256.trim(), ignoreCase = true))
        }
    }

    /**
     * Adds an application to the user's trusted whitelist.
     */
    fun addApp(context: Context, packageName: String, appName: String, sha256: String) {
        synchronized(whitelistLock) {
            val current = getWhitelistedApps(context).toMutableList()
            current.removeAll { it.packageName.equals(packageName.trim(), ignoreCase = true) }
            current.add(
                WhitelistedApp(
                    packageName = packageName.trim(),
                    appName = appName.ifBlank { packageName },
                    sha256 = sha256.trim(),
                    addedTimestamp = System.currentTimeMillis()
                )
            )
            saveWhitelistedApps(context, current)
            cachedWhitelistedApps = current.toList()
        }
    }

    /**
     * Removes an application from the user's trusted whitelist.
     */
    fun removeApp(context: Context, packageName: String) {
        synchronized(whitelistLock) {
            val current = getWhitelistedApps(context).toMutableList()
            current.removeAll { it.packageName.equals(packageName.trim(), ignoreCase = true) }
            saveWhitelistedApps(context, current)
            cachedWhitelistedApps = current.toList()
        }
    }

    /**
     * Retrieves all whitelisted applications.
     */
    fun getWhitelistedApps(context: Context): List<WhitelistedApp> {
        synchronized(whitelistLock) {
            cachedWhitelistedApps?.let { return it }
            val jsonStr = getPrefs(context).getString(KEY_WHITELISTED_JSON, null)
            if (jsonStr == null) {
                val empty = emptyList<WhitelistedApp>()
                cachedWhitelistedApps = empty
                return empty
            }
            val list = try {
                val array = JSONArray(jsonStr)
                val result = mutableListOf<WhitelistedApp>()
                for (i in 0 until array.length()) {
                    val obj = array.getJSONObject(i)
                    result.add(
                        WhitelistedApp(
                            packageName = obj.optString("packageName"),
                            appName = obj.optString("appName"),
                            sha256 = obj.optString("sha256"),
                            addedTimestamp = obj.optLong("addedTimestamp", System.currentTimeMillis())
                        )
                    )
                }
                result
            } catch (_: Exception) {
                emptyList()
            }
            cachedWhitelistedApps = list
            return list
        }
    }

    private fun saveWhitelistedApps(context: Context, apps: List<WhitelistedApp>) {
        val array = JSONArray()
        apps.forEach { app ->
            val obj = JSONObject()
            obj.put("packageName", app.packageName)
            obj.put("appName", app.appName)
            obj.put("sha256", app.sha256)
            obj.put("addedTimestamp", app.addedTimestamp)
            array.put(obj)
        }
        getPrefs(context).edit().putString(KEY_WHITELISTED_JSON, array.toString()).apply()
    }
}
