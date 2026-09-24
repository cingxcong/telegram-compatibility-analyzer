package app.tca

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import java.io.File
import java.util.zip.ZipEntry
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
