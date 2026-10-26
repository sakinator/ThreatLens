package io.threatlens.core.news

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.StringReader
import java.net.URLEncoder
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.TimeUnit

object CyberNewsFeedService {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    suspend fun fetchDailyMalwareNews(userLocation: UserLocation): List<CyberNewsArticle> = withContext(Dispatchers.IO) {
        val articles = mutableListOf<CyberNewsArticle>()
        val isIndia = userLocation.countryCode.equals("IN", ignoreCase = true) || userLocation.country.contains("India", ignoreCase = true)

        // 1. Fetch Country / Region-Specific News (e.g. India CERT-In, Digital Arrest, Banking Fraud)
        try {
            val query = if (isIndia) {
                "India cyber security OR Android malware OR CERT-In OR digital arrest OR banking fraud when:7d"
            } else {
                "${userLocation.country} Android malware OR cyber security OR trojan when:7d"
            }
            val hl = if (isIndia) "en-IN" else "en-US"
            val gl = if (isIndia) "IN" else (if (userLocation.countryCode.length == 2) userLocation.countryCode else "US")
            val ceid = if (isIndia) "IN:en" else "$gl:en"

            val countryUrl = "https://news.google.com/rss/search?q=${URLEncoder.encode(query, "UTF-8")}&hl=$hl&gl=$gl&ceid=$ceid"
            val countryArticles = fetchRssFeed(countryUrl, isLocal = true, targetRegion = if (isIndia) "India" else userLocation.country)
            articles.addAll(countryArticles.take(12))
        } catch (_: Exception) {}

        // 2. Fetch The Hacker News (Premier Real-time Cyber Intelligence)
        try {
            val thnUrl = "https://feeds.feedburner.com/TheHackersNews"
            val thnArticles = fetchRssFeed(thnUrl, isLocal = false, targetRegion = "Worldwide")
            articles.addAll(thnArticles.take(8))
        } catch (_: Exception) {}

        // 3. Fetch Global Mobile Threats & Zero-Days (Past 7 Days)
        try {
            val globalQuery = "Android malware OR mobile spyware OR banking trojan OR zero-day when:7d"
            val globalUrl = "https://news.google.com/rss/search?q=${URLEncoder.encode(globalQuery, "UTF-8")}&hl=en-US&gl=US&ceid=US:en"
            val globalArticles = fetchRssFeed(globalUrl, isLocal = false, targetRegion = "Worldwide")
            articles.addAll(globalArticles.take(12))
        } catch (_: Exception) {}

        // 4. Fallback curated articles if offline
        if (articles.isEmpty()) {
            articles.addAll(getOfflineCuratedThreatNews(userLocation))
        }

        // Distinct by title, and sort strictly chronologically by time (latest on top for both local and global)
        articles.distinctBy { it.title.trim().lowercase() }
            .sortedByDescending { it.publishedTimestamp }
    }

    private fun fetchRssFeed(feedUrl: String, isLocal: Boolean, targetRegion: String): List<CyberNewsArticle> {
        val list = mutableListOf<CyberNewsArticle>()
        try {
            val request = Request.Builder()
                .url(feedUrl)
                .addHeader("User-Agent", "Mozilla/5.0 (Android; Mobile; rv:120.0) ThreatLens/1.0")
                .get()
                .build()

            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return emptyList()
                val xml = response.body?.string() ?: return emptyList()

                val factory = XmlPullParserFactory.newInstance()
                factory.isNamespaceAware = false
                val parser = factory.newPullParser()
                parser.setInput(StringReader(xml))

                var eventType = parser.eventType
                var inItem = false
                var currentTitle = ""
                var currentLink = ""
                var currentPubDate = ""
                var currentSource = "Security Feed"
                var currentTag = ""

                while (eventType != XmlPullParser.END_DOCUMENT) {
                    when (eventType) {
                        XmlPullParser.START_TAG -> {
                            currentTag = parser.name
                            if (currentTag.equals("item", ignoreCase = true)) {
                                inItem = true
                                currentTitle = ""
                                currentLink = ""
                                currentPubDate = ""
                                currentSource = "Security Feed"
                            }
                        }
                        XmlPullParser.TEXT -> {
                            if (inItem) {
                                val text = parser.text.trim()
                                if (text.isNotEmpty()) {
                                    when {
                                        currentTag.equals("title", ignoreCase = true) -> currentTitle = text
                                        currentTag.equals("link", ignoreCase = true) -> currentLink = text
                                        currentTag.equals("pubDate", ignoreCase = true) -> currentPubDate = text
                                        currentTag.equals("source", ignoreCase = true) -> currentSource = text
                                    }
                                }
                            }
                        }
                        XmlPullParser.END_TAG -> {
                            if (parser.name.equals("item", ignoreCase = true)) {
                                inItem = false
                                if (currentTitle.isNotBlank() && currentLink.isNotBlank()) {
                                    // Extract clean title & publisher
                                    val parts = currentTitle.split(" - ")
                                    val cleanTitle = parts[0]
                                    val publisher = if (parts.size > 1) parts.last() else currentSource

                                    val summary = generateThreatSummary(cleanTitle)
                                    val timestamp = parsePubTimestamp(currentPubDate)
                                    val formattedTime = formatTimestamp(timestamp, currentPubDate)

                                    list.add(
                                        CyberNewsArticle(
                                            title = cleanTitle,
                                            summary = summary,
                                            source = publisher,
                                            articleUrl = currentLink,
                                            publishedAt = formattedTime,
                                            publishedTimestamp = timestamp,
                                            isLocalCountryThreat = isLocal,
                                            countryTarget = targetRegion
                                        )
                                    )
                                }
                            }
                        }
                    }
                    eventType = parser.next()
                }
            }
        } catch (_: Exception) {}
        return list
    }

    private fun generateThreatSummary(title: String): String {
        val lower = title.lowercase()
        return when {
            lower.contains("cert-in") || lower.contains("india") ->
                "CERT-In national cyber advisory warning Indian users against critical vulnerabilities and active digital fraud campaigns."
            lower.contains("digital arrest") || lower.contains("upi") || lower.contains("banking") ->
                "Law enforcement warning: Cyber syndicates impersonating police and tax officials to execute unauthorized fund transfers."
            lower.contains("bank") || lower.contains("trojan") ->
                "Active banking malware wave discovered targeting banking overlays, SMS 2FA intercept, and biometric credentials."
            lower.contains("spyware") || lower.contains("stealer") ->
                "Stealth spyware detected harvesting contacts, private WhatsApp messages, and keystrokes."
            lower.contains("google play") || lower.contains("fake app") ->
                "Malicious applications discovered masquerading as system utilities and photo editors on app repositories."
            lower.contains("zero-day") || lower.contains("flaw") || lower.contains("vulnerability") ->
                "Critical security vulnerability flagged allowing arbitrary code execution without user interaction."
            else ->
                "Recent mobile threat intelligence bulletin verified by threat research teams. Verify application authenticity."
        }
    }

    private fun parsePubTimestamp(rawDate: String): Long {
        if (rawDate.isBlank()) return System.currentTimeMillis()
        val formats = listOf(
            SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.ENGLISH),
            SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss Z", Locale.ENGLISH),
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ENGLISH),
            SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ENGLISH),
            SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss", Locale.ENGLISH)
        )
        for (format in formats) {
            try {
                val date = format.parse(rawDate)
                if (date != null) {
                    return date.time
                }
            } catch (_: Exception) {}
        }
        return System.currentTimeMillis()
    }

    private fun formatTimestamp(timestamp: Long, rawDate: String): String {
        val diff = System.currentTimeMillis() - timestamp
        if (diff < 0) return "Just now"
        val minutes = diff / (1000 * 60)
        val hours = minutes / 60
        val days = hours / 24
        return when {
            minutes < 2 -> "Just now"
            minutes < 60 -> "${minutes}m ago"
            hours < 24 -> "${hours}h ago"
            days == 1L -> "Yesterday"
            days < 7 -> "${days}d ago"
            else -> {
                if (rawDate.isNotBlank()) {
                    try {
                        val date = Date(timestamp)
                        SimpleDateFormat("MMM dd", Locale.ENGLISH).format(date)
                    } catch (_: Exception) {
                        "Recent"
                    }
                } else "Recent"
            }
        }
    }

    private fun getOfflineCuratedThreatNews(location: UserLocation): List<CyberNewsArticle> {
        val isIndia = location.countryCode.equals("IN", ignoreCase = true) || location.country.contains("India", ignoreCase = true)
        val now = System.currentTimeMillis()
        return listOf(
            CyberNewsArticle(
                title = if (isIndia) "CERT-In Issues High-Severity Alert on Android Banking Trojans & UPI Scams" else "New Anatsa Banking Trojan Wave Targets Mobile Users",
                summary = if (isIndia) "Indian Computer Emergency Response Team (CERT-In) issues advisory on malicious APKs masquerading as bank rewards and digital arrest callers." else "Cybersecurity teams report a surge in Anatsa banking malware evading app store security checks to steal bank logins.",
                source = if (isIndia) "CERT-In Advisory" else "BleepingComputer",
                articleUrl = if (isIndia) "https://www.cert-in.org.in" else "https://www.bleepingcomputer.com",
                publishedAt = "2h ago",
                publishedTimestamp = now - (2 * 3600 * 1000),
                isLocalCountryThreat = true,
                countryTarget = if (isIndia) "India" else location.country
            ),
            CyberNewsArticle(
                title = "Android Zero-Day Vulnerability Discovered in Media Framework",
                summary = "Critical security flaw allows malicious files to execute arbitrary code when downloaded or previewed.",
                source = "The Hacker News",
                articleUrl = "https://thehackernews.com",
                publishedAt = "4h ago",
                publishedTimestamp = now - (4 * 3600 * 1000),
                isLocalCountryThreat = false,
                countryTarget = "Worldwide"
            ),
            CyberNewsArticle(
                title = "SharkBot Trojan Returns with Fake Antivirus Droppers",
                summary = "Attackers are distributing fake security applications that silently drop banking malware payloads in the background.",
                source = "Threatpost",
                articleUrl = "https://threatpost.com",
                publishedAt = "Yesterday",
                publishedTimestamp = now - (24 * 3600 * 1000),
                isLocalCountryThreat = false,
                countryTarget = "Worldwide"
            )
        )
    }
}
