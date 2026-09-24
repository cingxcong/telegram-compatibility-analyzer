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

    fun load(path: java.io.File): FingerprintSet =
        mapper.readValue(path)

    fun loadJson(json: String): FingerprintSet =
        mapper.readValue(json)
}

object FingerprintMatcher {
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
                else -> FingerprintMatch(fp.id, "BROKEN", 0.0)
            }
        }
    }
}
