package io.threatlens.core.news

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.Locale
import java.util.concurrent.TimeUnit

object GeoLocationService {

    private val client = OkHttpClient.Builder()
        .connectTimeout(6, TimeUnit.SECONDS)
        .readTimeout(6, TimeUnit.SECONDS)
        .build()

    private var cachedLocation: UserLocation? = null

    suspend fun detectLocation(): UserLocation = withContext(Dispatchers.IO) {
        cachedLocation?.let { return@withContext it }

        // 1. Try HTTPS IP Geolocation from ipwho.is (100% free, full HTTPS, high accuracy)
        try {
            val request = Request.Builder()
                .url("https://ipwho.is/")
                .addHeader("User-Agent", "Mozilla/5.0 ThreatLens/1.0")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val raw = response.body?.string()
                    if (!raw.isNullOrBlank()) {
                        val json = JSONObject(raw)
                        if (json.optBoolean("success", true)) {
                            val country = json.optString("country", "")
                            val countryCode = json.optString("country_code", "")
                            if (country.isNotBlank() && countryCode.isNotBlank()) {
                                val flag = countryCodeToEmoji(countryCode)
                                val loc = UserLocation(country, countryCode, flag)
                                cachedLocation = loc
                                return@withContext loc
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        // 2. Secondary HTTPS Fallback: api.country.is
        try {
            val request = Request.Builder()
                .url("https://api.country.is/")
                .addHeader("User-Agent", "Mozilla/5.0 ThreatLens/1.0")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) {
                    val raw = response.body?.string()
                    if (!raw.isNullOrBlank()) {
                        val json = JSONObject(raw)
                        val countryCode = json.optString("country", "")
                        if (countryCode.isNotBlank() && countryCode.length == 2) {
                            val loc = Locale("", countryCode)
                            val countryName = loc.displayCountry.ifBlank { countryCode }
                            val flag = countryCodeToEmoji(countryCode)
                            val userLoc = UserLocation(countryName, countryCode, flag)
                            cachedLocation = userLoc
                            return@withContext userLoc
                        }
                    }
                }
            }
        } catch (_: Exception) {}

        // 3. Device System Locale Fallback (Guaranteed to work offline or when IP endpoints unreachable)
        try {
            val sysLocale = Locale.getDefault()
            val countryCode = sysLocale.country
            if (!countryCode.isNullOrBlank() && countryCode.length == 2) {
                val countryName = sysLocale.displayCountry.ifBlank {
                    if (countryCode.equals("IN", ignoreCase = true)) "India" else countryCode
                }
                val flag = countryCodeToEmoji(countryCode)
                val loc = UserLocation(countryName, countryCode, flag)
                cachedLocation = loc
                return@withContext loc
            }
        } catch (_: Exception) {}

        UserLocation("India", "IN", "🇮🇳")
    }

    private fun countryCodeToEmoji(countryCode: String): String {
        if (countryCode.length != 2) return "🌐"
        val upper = countryCode.uppercase(Locale.US)
        val firstChar = Character.codePointAt(upper, 0) - 0x41 + 0x1F1E6
        val secondChar = Character.codePointAt(upper, 1) - 0x41 + 0x1F1E6
        return String(Character.toChars(firstChar)) + String(Character.toChars(secondChar))
    }
}
