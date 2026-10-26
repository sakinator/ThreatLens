package io.threatlens.core.storage

import android.content.Context
import android.util.Log
import io.threatlens.core.realtime.RealtimeScanCoordinator
import org.json.JSONObject
import java.io.File

object ApiKeyVault {

    private const val TAG = "ApiKeyVault"
    private const val PREFS_NAME = "threatlens_prefs"
    private const val BACKUP_FILE_NAME = "threatlens_keys_vault_backup.json"

    val PROVIDER_KEYS = mapOf(
        "openai" to "openai_key",
        "claude" to "claude_key",
        "gemini" to "gemini_key",
        "groq" to "groq_key",
        "virustotal" to "vt_key",
        "hybridanalysis" to "ha_key",
        "kaspersky" to "kaspersky_key",
        "metadefender" to "metadefender_key",
        "filescan" to "filescan_key",
        "malwarebazaar" to "bazaar_key"
    )

    fun init(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val backupFile = File(context.filesDir, BACKUP_FILE_NAME)

        // 1. Check if backup file exists to restore any keys lost during app updates
        if (backupFile.exists()) {
            try {
                val json = JSONObject(backupFile.readText())
                val keysObj = if (json.has("keys")) json.getJSONObject("keys") else json
                val editor = prefs.edit()
                var restoredAny = false

                for ((provider, prefKey) in PROVIDER_KEYS) {
                    val currentVal = prefs.getString(prefKey, "") ?: ""
                    if (currentVal.isBlank() && keysObj.has(provider)) {
                        val backedUpKey = keysObj.getString(provider).trim()
                        if (backedUpKey.isNotBlank()) {
                            editor.putString(prefKey, backedUpKey)
                            restoredAny = true
                        }
                    }
                }
                if (restoredAny) {
                    editor.commit()
                    Log.i(TAG, "Restored missing cloud API keys from durable backup file")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Could not restore from backup file: ${e.message}")
            }
        }

        // 2. Synchronize current keys to backup file
        syncToBackupFile(context)

        // 3. Immediately propagate keys to RealtimeScanCoordinator so background scans have access
        syncToCoordinator(context)
    }

    fun syncToCoordinator(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        RealtimeScanCoordinator.openAiKey = prefs.getString("openai_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.claudeKey = prefs.getString("claude_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.geminiKey = prefs.getString("gemini_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.groqKey = prefs.getString("groq_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.virusTotalKey = prefs.getString("vt_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.hybridAnalysisKey = prefs.getString("ha_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.kasperskyKey = prefs.getString("kaspersky_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.metaDefenderKey = prefs.getString("metadefender_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.filescanKey = prefs.getString("filescan_key", "")?.trim()?.ifBlank { null }
        RealtimeScanCoordinator.bazaarKey = prefs.getString("bazaar_key", "")?.trim()?.ifBlank { null }
    }

    fun saveSingleKey(context: Context, provider: String, key: String) {
        val prefKey = when (provider.lowercase()) {
            "openai" -> "openai_key"
            "claude" -> "claude_key"
            "gemini" -> "gemini_key"
            "groq" -> "groq_key"
            "vt", "virustotal" -> "vt_key"
            "ha", "hybridanalysis" -> "ha_key"
            "kaspersky" -> "kaspersky_key"
            "metadefender" -> "metadefender_key"
            "filescan" -> "filescan_key"
            "bazaar", "malwarebazaar", "abusech" -> "bazaar_key"
            else -> return
        }
        val trimmed = key.trim()
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        // Use synchronous commit() to ensure immediate durability across crashes or app updates
        prefs.edit().putString(prefKey, trimmed).commit()

        syncToBackupFile(context)
        syncToCoordinator(context)
    }

    fun saveAllKeys(
        context: Context,
        openai: String,
        claude: String,
        gemini: String,
        groq: String,
        vt: String,
        ha: String,
        kaspersky: String,
        metaDefender: String,
        filescan: String,
        bazaar: String
    ) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString("openai_key", openai.trim())
            .putString("claude_key", claude.trim())
            .putString("gemini_key", gemini.trim())
            .putString("groq_key", groq.trim())
            .putString("vt_key", vt.trim())
            .putString("ha_key", ha.trim())
            .putString("kaspersky_key", kaspersky.trim())
            .putString("metadefender_key", metaDefender.trim())
            .putString("filescan_key", filescan.trim())
            .putString("bazaar_key", bazaar.trim())
            .commit()

        syncToBackupFile(context)
        syncToCoordinator(context)
    }

    private fun syncToBackupFile(context: Context) {
        try {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val root = JSONObject()
            root.put("version", 1)
            root.put("updated_at", System.currentTimeMillis())

            val keys = JSONObject()
            for ((provider, prefKey) in PROVIDER_KEYS) {
                val value = prefs.getString(prefKey, "") ?: ""
                if (value.isNotBlank()) {
                    keys.put(provider, value)
                }
            }
            root.put("keys", keys)

            val backupFile = File(context.filesDir, BACKUP_FILE_NAME)
            backupFile.writeText(root.toString(2))
        } catch (e: Exception) {
            Log.w(TAG, "Failed writing keys backup file: ${e.message}")
        }
    }

    fun exportKeysJson(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val root = JSONObject()
        root.put("app", "ThreatLens")
        root.put("version", 1)
        root.put("exported_at", System.currentTimeMillis())

        val keys = JSONObject()
        var count = 0
        for ((provider, prefKey) in PROVIDER_KEYS) {
            val value = prefs.getString(prefKey, "") ?: ""
            if (value.isNotBlank()) {
                keys.put(provider, value)
                count++
            }
        }
        root.put("key_count", count)
        root.put("keys", keys)
        return root.toString(2)
    }

    fun importKeysJson(context: Context, jsonStr: String): Pair<Int, String> {
        val trimmed = jsonStr.trim()
        if (trimmed.isBlank()) {
            return Pair(0, "Import payload is empty")
        }

        try {
            val root = JSONObject(trimmed)
            val keysObj = when {
                root.has("keys") -> root.getJSONObject("keys")
                else -> root
            }

            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val editor = prefs.edit()
            var importedCount = 0

            for ((provider, prefKey) in PROVIDER_KEYS) {
                val keyFromProvider = if (keysObj.has(provider)) keysObj.optString(provider) else null
                val keyFromPrefKey = if (keysObj.has(prefKey)) keysObj.optString(prefKey) else null
                val candidate = (keyFromProvider ?: keyFromPrefKey)?.trim() ?: ""

                if (candidate.isNotBlank()) {
                    editor.putString(prefKey, candidate)
                    importedCount++
                }
            }

            if (importedCount > 0) {
                editor.commit()
                syncToBackupFile(context)
                syncToCoordinator(context)
                return Pair(importedCount, "Successfully imported $importedCount API key(s)!")
            } else {
                return Pair(0, "No valid ThreatLens API keys found in JSON payload")
            }
        } catch (e: Exception) {
            return Pair(0, "Invalid JSON format: ${e.message}")
        }
    }
}
