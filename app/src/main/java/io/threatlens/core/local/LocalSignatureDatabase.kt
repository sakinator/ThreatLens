package io.threatlens.core.local

/**
 * High-speed offline signature cache.
 * Matches known malware SHA-256 hashes instantly before calling the network.
 */
object LocalSignatureDatabase {

    data class SignatureEntry(
        val threatFamily: String,
        val category: String,
        val baseScore: Int
    )

    private val signatureMap = HashMap<String, SignatureEntry>().apply {
        // Banking Trojans (Cerberus, Anatsa, SharkBot, Teabot)
        put("3a6f44d8c6b75f9227181c009bdc8c1873130d2105aa0a6c085fc5794a37b089", 
            SignatureEntry("Trojan-Banker.AndroidOS.Cerberus", "Banking Trojan", 100))
        put("8f8e02d415b3c2e11899e4b60e6e9b4032d94cf3261a8684ad4bb25a3d077b94", 
            SignatureEntry("Trojan.AndroidOS.SharkBot", "Banking Trojan", 100))
        put("b3c8f8d637c385b0aa766468cb32f9156e9c9b9ecadceee7bc805a41753c1d91",
            SignatureEntry("Trojan-Banker.AndroidOS.Anatsa", "Banking Trojan", 100))

        // Spyware & SMS Stealers
        put("5c17d23a1a67cb88a6d6d45e4a77914e6b1297e6e58b8f36c57f920272c418ff", 
            SignatureEntry("Trojan-Spy.AndroidOS.SmsStealer", "Spyware", 95))
        put("1e2a0b1290384a32dc5c7f89781a94b5952ca2e6e3c0f4569c73df8914620021",
            SignatureEntry("Spyware.AndroidOS.Spynote", "Spyware / RAT", 100))

        // Adware & Toll Fraud
        put("0b5cf818c325bc12e604f3513a96860db3fcfa8cf0f23e60249c55b6efc6f376", 
            SignatureEntry("Trojan.AndroidOS.Joker", "Toll Fraud / Billing", 90))
        put("6a8b13994e09f582d95015b61ff6f2dca58d8442e5661c9b68cb2622f6fa7311",
            SignatureEntry("Adware.AndroidOS.HiddenAds", "Aggressive Adware", 65))
    }

    fun lookup(sha256: String): SignatureEntry? {
        return signatureMap[sha256.lowercase()]
    }

    fun registerSignature(sha256: String, family: String, category: String, score: Int) {
        signatureMap[sha256.lowercase()] = SignatureEntry(family, category, score)
    }

    val totalSignatures: Int
        get() = signatureMap.size
}
