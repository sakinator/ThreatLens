package io.threatlens.core.local

import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

object HashUtil {

    fun sha256(file: File): String {
        return hash(file, "SHA-256")
    }

    fun md5(file: File): String {
        return hash(file, "MD5")
    }

    private fun hash(file: File, algorithm: String): String {
        if (!file.exists() || !file.canRead()) return ""
        val digest = MessageDigest.getInstance(algorithm)
        FileInputStream(file).use { fis ->
            val buffer = ByteArray(16384)
            var bytesRead: Int
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
