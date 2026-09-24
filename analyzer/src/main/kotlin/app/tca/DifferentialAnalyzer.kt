package app.tca

data class MigrationCandidate(
    val signature: String,
    val combinedScore: Double,
    val structuralScore: Double,
    val classContextScore: Double,
    val callContextScore: Double
)

data class MethodMigration(
    val oldSignature: String,
    val newSignature: String? = null,
    val status: String,
    val confidence: Double,
    val candidates: List<MigrationCandidate> = emptyList(),
    val classContextConfidence: Double? = null
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
    private const val CLASS_CONTEXT_WEIGHT = 0.12
    private const val CALL_CONTEXT_WEIGHT = 0.20

    private data class ScoredMethod(
        val method: MethodIndex,
        val structuralScore: Double,
        val classContextScore: Double,
        val callContextScore: Double,
        val neighborhoodScore: Double
    ) {
        val combinedScore: Double
            get() {
                val classWeight = if (classContextScore > 0.0) CLASS_CONTEXT_WEIGHT else 0.0
                val callWeight = if (callContextScore > 0.0) CALL_CONTEXT_WEIGHT else 0.0
                val structuralWeight = 1.0 - classWeight - callWeight
                return structuralScore * structuralWeight +
                    classContextScore * classWeight +
                    callContextScore * callWeight
            }
    }

    fun compare(
        oldMetadata: ApkMetadata,
        newMetadata: ApkMetadata,
        oldIndexes: List<DexIndex>,
        newIndexes: List<DexIndex>
    ): DifferentialReport {
        val oldMethods = oldIndexes.flatMap { it.methods }
        val newMethods = newIndexes.flatMap { it.methods }
        val newBySignature = newMethods.associateBy { it.signature }
        val newByPrototype = newMethods.groupBy { it.returnType to it.parameterTypes }
        val oldClasses = oldIndexes.flatMap { it.classes }
        val newClasses = newIndexes.flatMap { it.classes }
        val classMappings = buildClassMappings(oldClasses, newClasses)

        val migrations = oldMethods.asSequence()
            .filter { old -> newBySignature[old.signature] == null }
            .map { old ->
                migrate(
                    old,
                    newByPrototype[old.returnType to old.parameterTypes].orEmpty(),
                    classMappings
                )
            }
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

    private fun migrate(
        old: MethodIndex,
        newMethods: List<MethodIndex>,
        classMappings: Map<String, ClassMapping>
    ): MethodMigration {
        val mappedClass = classMappings[old.definingClass]
        val candidates = newMethods.asSequence()
            .map { method ->
                val structural = FingerprintMatcher.score(old, method)
                val classContext = mappedClass?.let { mapping ->
                    if (mapping.newClass == method.definingClass) mapping.confidence else 0.0
                } ?: 0.0
                val callContext = callPrototypeSimilarity(old.callPrototypeHistogram, method.callPrototypeHistogram)
                val neighborhood = targetOverlap(old.callTargetHistogram, method.callTargetHistogram)
                ScoredMethod(method, structural, classContext, callContext, neighborhood)
            }
            .filter { it.structuralScore > 0.0 }
            .sortedByDescending { it.combinedScore }
            .take(10)
            .toList()

        if (candidates.isEmpty()) {
            return MethodMigration(old.signature, status = "BROKEN", confidence = 0.0)
        }

        val best = candidates.first()
        val second = candidates.getOrNull(1)?.combinedScore ?: 0.0
        val margin = best.combinedScore - second
        val status = if (best.combinedScore >= MIGRATED_THRESHOLD && margin >= MARGIN_THRESHOLD) {
            "MIGRATED"
        } else {
            "REVIEW"
        }

        return MethodMigration(
            oldSignature = old.signature,
            newSignature = if (status == "MIGRATED") best.method.signature else null,
            status = status,
            confidence = best.combinedScore.coerceIn(0.0, 1.0),
            candidates = candidates.map {
                MigrationCandidate(
                    signature = it.method.signature,
                    combinedScore = it.combinedScore,
                    structuralScore = it.structuralScore,
                    classContextScore = it.classContextScore,
                    callContextScore = it.callContextScore
                )
            },
            classContextConfidence = mappedClass?.confidence
        )
    }

    private fun targetOverlap(old: Map<String, Int>, current: Map<String, Int>): Double {
        if (old.isEmpty() && current.isEmpty()) return 1.0
        if (old.isEmpty() || current.isEmpty()) return 0.0
        val oldKeys = old.keys
        val currentKeys = current.keys
        return oldKeys.intersect(currentKeys).size.toDouble() / oldKeys.union(currentKeys).size.toDouble()
    }

    private fun callPrototypeSimilarity(old: Map<String, Int>, current: Map<String, Int>): Double {
        if (old.isEmpty() && current.isEmpty()) return 1.0
        if (old.isEmpty() || current.isEmpty()) return 0.0
        val keys = old.keys union current.keys
        val oldTotal = old.values.sum().coerceAtLeast(1)
        val currentTotal = current.values.sum().coerceAtLeast(1)
        val distance = keys.sumOf { key ->
            kotlin.math.abs(
                old.getOrDefault(key, 0).toDouble() / oldTotal -
                    current.getOrDefault(key, 0).toDouble() / currentTotal
            )
        }
        return (1.0 - distance / 2.0).coerceIn(0.0, 1.0)
    }

    private data class ClassMapping(
        val newClass: String,
        val confidence: Double
    )

    private fun buildClassMappings(
        oldClasses: List<ClassIndex>,
        newClasses: List<ClassIndex>
    ): Map<String, ClassMapping> {
        val newByShape = newClasses.groupBy { it.methodCount to it.fieldCount }
        return oldClasses.mapNotNull { old ->
            val candidates = newByShape[old.methodCount to old.fieldCount].orEmpty()
                .map { it to classSimilarity(old, it) }
                .sortedByDescending { it.second }
                .take(2)

            val best = candidates.firstOrNull() ?: return@mapNotNull null
            val second = candidates.getOrNull(1)?.second ?: 0.0
            val margin = best.second - second
            if (best.second < 0.80 || margin < 0.05) return@mapNotNull null

            old.type to ClassMapping(best.first.type, best.second)
        }.toMap()
    }

    private fun classSimilarity(old: ClassIndex, current: ClassIndex): Double {
        val methodShape = kotlin.math.min(old.methodCount, current.methodCount).toDouble() /
            maxOf(old.methodCount, current.methodCount).coerceAtLeast(1)
        val fieldShape = kotlin.math.min(old.fieldCount, current.fieldCount).toDouble() /
            maxOf(old.fieldCount, current.fieldCount).coerceAtLeast(1)
        val interfaceShape = jaccard(old.interfaces.toSet(), current.interfaces.toSet())
        val accessShape = if (old.accessFlags == current.accessFlags) 1.0 else 0.5
        return methodShape * 0.45 + fieldShape * 0.20 + interfaceShape * 0.20 + accessShape * 0.15
    }

    private fun jaccard(old: Set<String>, current: Set<String>): Double {
        if (old.isEmpty() && current.isEmpty()) return 1.0
        if (old.isEmpty() || current.isEmpty()) return 0.0
        return old.intersect(current).size.toDouble() / old.union(current).size.toDouble()
    }

    private fun apkMap(metadata: ApkMetadata): Map<String, Any?> = mapOf(
        "packageName" to metadata.packageName,
        "versionName" to metadata.versionName,
        "versionCode" to metadata.versionCode,
        "sha256" to metadata.sha256,
        "dexCount" to metadata.dexEntries.size
    )
}
