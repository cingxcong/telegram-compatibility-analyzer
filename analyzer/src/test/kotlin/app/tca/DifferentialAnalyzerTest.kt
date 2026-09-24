package app.tca

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DifferentialAnalyzerTest {
    @Test
    fun renamedMethodIsReportedAsMigration() {
        val oldMethod = MethodIndex(
            "Lold/ActionBar/r2;",
            "isSwipeBackEnabled",
            "Z",
            listOf("Landroid/view/MotionEvent;"),
            1,
            7,
            2,
            mapOf("IGET_BOOLEAN" to 1, "RETURN" to 1),
            "Ljava/lang/Object;",
            emptyList()
        )
        val newMethod = oldMethod.copy(
            definingClass = "Lnew/ActionBar/q2;",
            opcodeHistogram = oldMethod.opcodeHistogram
        )

        val report = DifferentialAnalyzer.compare(
            metadata("12.10.3", 70892, "old"),
            metadata("12.10.4", 70992, "new"),
            listOf(DexIndex("classes.dex", 1, 1, emptyList(), listOf(oldMethod))),
            listOf(DexIndex("classes.dex", 1, 1, emptyList(), listOf(newMethod)))
        )

        val migration = report.migrations.single()
        assertEquals("MIGRATED", migration.status)
        assertEquals(newMethod.signature, migration.newSignature)
        assertTrue(migration.confidence >= 0.95)
    }

    @Test
    fun ambiguousRenameRequiresReview() {
        val oldMethod = MethodIndex(
            "Lold/A;",
            "probe",
            "Z",
            listOf("I"),
            1,
            4,
            2,
            mapOf("RETURN" to 1)
        )
        val newMethods = listOf(
            oldMethod.copy(definingClass = "Lnew/A;"),
            oldMethod.copy(definingClass = "Lnew/B;")
        )

        val report = DifferentialAnalyzer.compare(
            metadata("old", 1, "old"),
            metadata("new", 2, "new"),
            listOf(DexIndex("classes.dex", 1, 1, emptyList(), listOf(oldMethod))),
            listOf(DexIndex("classes.dex", 2, 2, emptyList(), newMethods))
        )

        assertEquals("REVIEW", report.migrations.single().status)
        assertTrue(report.migrations.single().newSignature == null)
    }

    private fun metadata(version: String, code: Int, sha: String) = ApkMetadata(
        path = version,
        sha256 = sha,
        packageName = "org.telegram.messenger",
        versionName = version,
        versionCode = code.toLong(),
        dexEntries = listOf("classes.dex"),
        nativeLibraries = emptyList(),
        sizeBytes = 1
    )
}
