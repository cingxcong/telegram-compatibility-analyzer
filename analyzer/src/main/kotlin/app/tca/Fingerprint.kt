package app.tca

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue

data class Fingerprint(
    val id: String,
    val definingClass: String? = null,
    val name: String? = null,
    val returnType: String? = null,
    val parameterTypes: List<String> = emptyList(),
    val instructionCount: Int? = null,
    val registerCount: Int? = null,
    val opcodeHistogram: Map<String, Int> = emptyMap(),
    val classSuperType: String? = null,
    val classInterfaces: List<String> = emptyList(),
    val tags: List<String> = emptyList(),
    val automation: String = "review"
)

data class FingerprintSet(
    val schemaVersion: String,
    val fingerprints: List<Fingerprint>
)

data class FingerprintMatch(
    val id: String,
    val status: String,
    val confidence: Double,
    val matchedSignature: String? = null,
    val candidates: List<String> = emptyList()
)

object FingerprintLoader {
    private val mapper = ObjectMapper().findAndRegisterModules()

    fun load(path: java.io.File): FingerprintSet = mapper.readValue(path)
    fun loadJson(json: String): FingerprintSet = mapper.readValue(json)
}

object FingerprintMatcher {
    private data class ScoredCandidate(val method: MethodIndex, val score: Double)

    fun match(indexes: List<DexIndex>, fingerprints: List<Fingerprint>): List<FingerprintMatch> {
        val methods = indexes.flatMap { it.methods }
        return fingerprints.map { fp ->
            val exact = methods.filter { method ->
                (fp.definingClass == null || method.definingClass == fp.definingClass) &&
                    (fp.name == null || method.name == fp.name) &&
                    (fp.returnType == null || method.returnType == fp.returnType) &&
                    (fp.parameterTypes.isEmpty() || method.parameterTypes == fp.parameterTypes) &&
                    (fp.instructionCount == null || method.instructionCount == fp.instructionCount)
            }

            when {
                exact.size == 1 -> FingerprintMatch(fp.id, "EXACT", 1.0, exact.single().signature)
                exact.size > 1 -> FingerprintMatch(
                    fp.id, "REVIEW", 0.9, candidates = exact.take(20).map { it.signature }
                )
                else -> structuralMatch(methods, fp)
            }
        }
    }

    private fun structuralMatch(methods: List<MethodIndex>, fp: Fingerprint): FingerprintMatch {
        val candidates = methods.asSequence()
            .filter { method ->
                (fp.returnType == null || method.returnType == fp.returnType) &&
                    (fp.parameterTypes.isEmpty() || method.parameterTypes == fp.parameterTypes)
            }
            .map { method -> ScoredCandidate(method, StructuralSimilarity.score(method, fp)) }
            .filter { it.score > 0.0 }
            .sortedByDescending { it.score }
            .take(20)
            .toList()

        if (candidates.isEmpty()) return FingerprintMatch(fp.id, "BROKEN", 0.0)

        val best = candidates.first()
        val second = candidates.getOrNull(1)?.score ?: 0.0
        val margin = best.score - second

        return if (best.score >= 0.95 && margin >= 0.08) {
            FingerprintMatch(
                fp.id,
                "MIGRATED",
                best.score.coerceIn(0.0, 1.0),
                matchedSignature = best.method.signature,
                candidates = candidates.take(5).map { formatCandidate(it) }
            )
        } else {
            FingerprintMatch(
                fp.id,
                "REVIEW",
                best.score.coerceIn(0.0, 1.0),
                candidates = candidates.take(10).map { formatCandidate(it) }
            )
        }
    }

    private fun formatCandidate(candidate: ScoredCandidate): String =
        "%.4f %s".format(java.util.Locale.ROOT, candidate.score, candidate.method.signature)

    fun score(method: MethodIndex, fp: Fingerprint): Double {
        var total = 0.0
        var weight = 0.0

        fun add(value: Double, w: Double) {
            total += value * w
            weight += w
        }

        if (fp.returnType != null) add(if (method.returnType == fp.returnType) 1.0 else 0.0, 0.20)
        if (fp.parameterTypes.isNotEmpty()) {
            add(if (method.parameterTypes == fp.parameterTypes) 1.0 else 0.0, 0.20)
        }
        if (fp.instructionCount != null) {
            add(similarity(fp.instructionCount.toDouble(), method.instructionCount.toDouble()), 0.20)
        }
        if (fp.registerCount != null) {
            add(similarity(fp.registerCount.toDouble(), method.registerCount.toDouble()), 0.10)
        }
        if (fp.opcodeHistogram.isNotEmpty()) {
            add(histogramSimilarity(fp.opcodeHistogram, method.opcodeHistogram), 0.25)
        }
        if (fp.classSuperType != null || fp.classInterfaces.isNotEmpty()) {
            val superScore = if (fp.classSuperType == null) 1.0
            else if (method.classSuperType == fp.classSuperType) 1.0 else 0.0
            val interfaceScore = if (fp.classInterfaces.isEmpty()) 1.0
            else jaccard(fp.classInterfaces.toSet(), method.classInterfaces.toSet())
            add((superScore + interfaceScore) / 2.0, 0.05)
        }

        return if (weight == 0.0) 0.0 else total / weight
    }

    fun score(old: MethodIndex, current: MethodIndex): Double =
        score(
            current,
            Fingerprint(
                id = old.signature,
                returnType = old.returnType,
                parameterTypes = old.parameterTypes,
                instructionCount = old.instructionCount,
                registerCount = old.registerCount,
                opcodeHistogram = old.opcodeHistogram,
                classSuperType = old.classSuperType,
                classInterfaces = old.classInterfaces
            )
        )

    private fun similarity(expected: Double, actual: Double): Double {
        if (expected == 0.0 && actual == 0.0) return 1.0
        if (expected == 0.0 || actual == 0.0) return 0.0
        return 1.0 - (kotlin.math.abs(expected - actual) / maxOf(expected, actual)).coerceIn(0.0, 1.0)
    }

    private fun histogramSimilarity(expected: Map<String, Int>, actual: Map<String, Int>): Double {
        val keys = expected.keys + actual.keys
        val expectedTotal = expected.values.sum().coerceAtLeast(1)
        val actualTotal = actual.values.sum().coerceAtLeast(1)
        val distance = keys.distinct().sumOf { opcode ->
            kotlin.math.abs(
                expected.getOrDefault(opcode, 0).toDouble() / expectedTotal -
                    actual.getOrDefault(opcode, 0).toDouble() / actualTotal
            )
        }
        return (1.0 - distance / 2.0).coerceIn(0.0, 1.0)
    }

    private fun jaccard(expected: Set<String>, actual: Set<String>): Double {
        if (expected.isEmpty() && actual.isEmpty()) return 1.0
        if (expected.isEmpty() || actual.isEmpty()) return 0.0
        return expected.intersect(actual).size.toDouble() / expected.union(actual).size.toDouble()
    }
}
