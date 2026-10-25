package io.threatlens.core.news

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object GeoLocationService {

    private val client = OkHttpClient.Builder()
        .connectTimeout(5, TimeUnit.SECONDS)
        .readTimeout(5, TimeUnit.SECONDS)
        .build()

    private var cachedLocation: UserLocation? = null

    suspend fun detectLocation(): UserLocation = withContext(Dispatchers.IO) {
        cachedLocation?.let { return@withContext it }

        try {
            val request = Request.Builder()
                .url("http://ip-api.com/json/")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@withContext UserLocation()
                val raw = response.body?.string() ?: return@withContext UserLocation()
                val json = JSONObject(raw)

                if (json.optString("status") == "success") {
                    val country = json.optString("country", "Global")
                    val countryCode = json.optString("countryCode", "GLOBAL")
                    val flag = countryCodeToEmoji(countryCode)
                    val loc = UserLocation(country, countryCode, flag)
                    cachedLocation = loc
                    return@withContext loc
                }
            }
        } catch (_: Exception) {}

        UserLocation()
    }

    private fun countryCodeToEmoji(countryCode: String): String {
        if (countryCode.length != 2) return "🌐"
        val firstChar = Character.codePointAt(countryCode, 0) - 0x41 + 0x1F1E6
        val secondChar = Character.codePointAt(countryCode, 1) - 0x41 + 0x1F1E6
        return String(Character.toChars(firstChar)) + String(Character.toChars(secondChar))
    }
}
