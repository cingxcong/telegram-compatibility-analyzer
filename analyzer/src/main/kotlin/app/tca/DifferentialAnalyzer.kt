package app.tca

data class MethodMigration(
    val oldSignature: String,
    val newSignature: String? = null,
    val status: String,
    val confidence: Double,
    val candidates: List<String> = emptyList()
)

data class DifferentialReport(
    val schemaVersion: String = "1",
    val oldApk: Map<String, Any?>,
    val newApk: Map<String, Any?>,
    val summary: Map<String, Int>,
    val migrations: List<MethodMigration>
)

object DifferentialAnalyzer {
    private const val MIGRATED_THRESHOLD = 0.95
    private const val MARGIN_THRESHOLD = 0.08

    fun compare(
        oldMetadata: ApkMetadata,
        newMetadata: ApkMetadata,
        oldIndexes: List<DexIndex>,
        newIndexes: List<DexIndex>
    ): DifferentialReport {
        val oldMethods = oldIndexes.flatMap { it.methods }
        val newMethods = newIndexes.flatMap { it.methods }
        val newBySignature = newMethods.associateBy { it.signature }

        val migrations = oldMethods.asSequence()
            .filter { old -> newBySignature[old.signature] == null }
            .map { old -> migrate(old, newMethods) }
            .filter { it.status != "UNCHANGED" }
            .sortedWith(compareBy<MethodMigration> { it.status }.thenByDescending { it.confidence })
            .toList()

        return DifferentialReport(
            oldApk = apkMap(oldMetadata),
            newApk = apkMap(newMetadata),
            summary = mapOf(
                "oldMethods" to oldMethods.size,
                "newMethods" to newMethods.size,
                "unchangedMethods" to oldMethods.count { newBySignature.containsKey(it.signature) },
                "migratedMethods" to migrations.count { it.status == "MIGRATED" },
                "reviewMethods" to migrations.count { it.status == "REVIEW" },
                "brokenMethods" to migrations.count { it.status == "BROKEN" }
            ),
            migrations = migrations
        )
    }

    private fun migrate(old: MethodIndex, newMethods: List<MethodIndex>): MethodMigration {
        val candidates = newMethods.asSequence()
            .filter { it.returnType == old.returnType && it.parameterTypes == old.parameterTypes }
            .map { it to StructuralSimilarity.score(old, it) }
            .filter { it.second > 0.0 }
            .sortedByDescending { it.second }
            .take(10)
            .toList()

        if (candidates.isEmpty()) {
            return MethodMigration(old.signature, status = "BROKEN", confidence = 0.0)
        }

        val best = candidates.first()
        val second = candidates.getOrNull(1)?.second ?: 0.0
        val margin = best.second - second
        val status = if (best.second >= MIGRATED_THRESHOLD && margin >= MARGIN_THRESHOLD) {
            "MIGRATED"
        } else {
            "REVIEW"
        }

        return MethodMigration(
            oldSignature = old.signature,
            newSignature = if (status == "MIGRATED") best.first.signature else null,
            status = status,
            confidence = best.second.coerceIn(0.0, 1.0),
            candidates = candidates.map { "%.4f %s".format(java.util.Locale.ROOT, it.second, it.first.signature) }
        )
    }

    private fun apkMap(metadata: ApkMetadata): Map<String, Any?> = mapOf(
        "packageName" to metadata.packageName,
        "versionName" to metadata.versionName,
        "versionCode" to metadata.versionCode,
        "sha256" to metadata.sha256,
        "dexCount" to metadata.dexEntries.size
    )
}
