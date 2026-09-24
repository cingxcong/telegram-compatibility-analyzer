package app.tca

import net.dongliu.apk.parser.ApkFile
import java.io.File
import java.security.MessageDigest
import java.util.zip.ZipFile

data class ApkMetadata(
    val path: String,
    val sha256: String,
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long?,
    val dexEntries: List<String>,
    val nativeLibraries: List<String>,
    val sizeBytes: Long
)

object ApkIntake {
    fun inspect(path: String): ApkMetadata {
        val file = File(path)
        require(file.isFile) { "APK does not exist: " + path }

        val dexEntries = mutableListOf<String>()
        val nativeLibraries = mutableListOf<String>()

        ZipFile(file).use { zip ->
            zip.entries().asSequence().forEach { entry ->
                when {
                    entry.name.matches(Regex("classes\\d*\\.dex")) -> dexEntries += entry.name
                    entry.name.startsWith("lib/") && entry.name.endsWith(".so") -> nativeLibraries += entry.name
                }
            }
        }

        val manifest = runCatching {
            ApkFile(file).use { apk -> apk.apkMeta }
        }.getOrNull()

        return ApkMetadata(
            path = file.absolutePath,
            sha256 = sha256(file),
            packageName = manifest?.packageName,
            versionName = manifest?.versionName,
            versionCode = manifest?.versionCode,
            dexEntries = dexEntries.sortedWith(compareBy<String> { dexNumber(it) }.thenBy { it }),
            nativeLibraries = nativeLibraries.sorted(),
            sizeBytes = file.length()
        )
    }

    private fun dexNumber(name: String): Int =
        if (name == "classes.dex") 1
        else Regex("classes(\\d+)\\.dex").matchEntire(name)?.groupValues?.get(1)?.toInt() ?: Int.MAX_VALUE

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
}
