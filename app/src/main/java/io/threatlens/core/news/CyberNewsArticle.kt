package io.threatlens.core.news

data class CyberNewsArticle(
    val id: String = java.util.UUID.randomUUID().toString(),
    val title: String,
    val summary: String,
    val source: String,
    val articleUrl: String,
    val publishedAt: String,
    val isLocalCountryThreat: Boolean = false,
    val countryTarget: String? = null
)

data class UserLocation(
    val country: String = "Global",
    val countryCode: String = "GLOBAL",
    val flagEmoji: String = "🌐"
)
