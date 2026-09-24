package app.tca

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import java.io.File
import java.util.zip.ZipEntry
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.util.zip.ZipOutputStream

class ApkIntakeTest {
    @Test
    fun discoversDexAndNativeEntries() {
        val apk = File.createTempFile("tca-test", ".apk")
        apk.deleteOnExit()

        ZipOutputStream(apk.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("classes.dex"))
            zip.write(byteArrayOf(0x64, 0x65, 0x78))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("classes2.dex"))
            zip.write(byteArrayOf(0x64, 0x65, 0x78))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("lib/arm64-v8a/libexample.so"))
            zip.write(byteArrayOf(1, 2, 3))
            zip.closeEntry()
        }

        val result = ApkIntake.inspect(apk.absolutePath)
        assertEquals(listOf("classes.dex", "classes2.dex"), result.dexEntries)
        assertEquals(listOf("lib/arm64-v8a/libexample.so"), result.nativeLibraries)
        assertEquals(64, result.sha256.length)
        assertTrue(result.sizeBytes > 0)
    }
}


    @Test
    fun loadsSha256KeyedDexIndexFromCache() {
        val apk = File.createTempFile("tca-cache-test", ".apk")
        val cacheDir = File.createTempFile("tca-cache", "").apply {
            delete()
            mkdirs()
        }
        apk.deleteOnExit()
        cacheDir.deleteOnExit()

        val cached = listOf(
            DexIndex(
                "classes.dex",
                1,
                1,
                listOf(ClassIndex("Lexample/Test;", "Ljava/lang/Object;", emptyList(), 1, 1, 0)),
                listOf(
                    MethodIndex(
                        "Lexample/Test;", "probe", "Z", emptyList(), 1, 1, 1,
                        mapOf("RETURN" to 1)
                    )
                )
            )
        )
        val sha = "a".repeat(64)
        val cacheFile = File(cacheDir, "$sha-api35-v1.json")
        jacksonObjectMapper().writeValue(cacheFile, cached)

        val result = DexIndexer.indexApkCached(apk, sha, cacheDir = cacheDir)
        assertEquals(cached, result)
    }
