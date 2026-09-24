package app.tca

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FingerprintMatcherTest {
    @Test
    fun exactSignatureMatchIsReported() {
        val method = MethodIndex(
            definingClass = "Lexample/Test;",
            name = "probe",
            returnType = "Z",
            parameterTypes = listOf("I"),
            accessFlags = 1,
            instructionCount = 3,
            registerCount = 2,
            opcodeHistogram = mapOf("CONST_4" to 1, "RETURN" to 1)
        )
        val index = DexIndex("classes.dex", 1, 1, emptyList(), listOf(method))
        val fingerprint = Fingerprint(
            id = "test.probe",
            definingClass = "Lexample/Test;",
            name = "probe",
            returnType = "Z",
            parameterTypes = listOf("I")
        )

        val result = FingerprintMatcher.match(listOf(index), listOf(fingerprint)).single()

        assertEquals("EXACT", result.status)
        assertEquals(1.0, result.confidence)
        assertEquals(method.signature, result.matchedSignature)
    }

    @Test
    fun structuralMigrationIsDetected() {
        val oldShape = Fingerprint(
            id = "test.migrated",
            definingClass = "Lold/Obfuscated;",
            name = "a",
            returnType = "Z",
            parameterTypes = listOf("I"),
            instructionCount = 4,
            registerCount = 3,
            opcodeHistogram = mapOf("CONST_4" to 1, "IF_EQZ" to 1, "RETURN" to 2)
        )
        val migrated = MethodIndex(
            definingClass = "Lnew/Obfuscated;",
            name = "b",
            returnType = "Z",
            parameterTypes = listOf("I"),
            accessFlags = 1,
            instructionCount = 4,
            registerCount = 3,
            opcodeHistogram = mapOf("CONST_4" to 1, "IF_EQZ" to 1, "RETURN" to 2)
        )
        val result = FingerprintMatcher.match(
            listOf(DexIndex("classes.dex", 1, 1, emptyList(), listOf(migrated))),
            listOf(oldShape)
        ).single()

        assertEquals("MIGRATED", result.status)
        assertEquals(migrated.signature, result.matchedSignature)
        assertTrue(result.confidence >= 0.95)
    }

    @Test
    fun controlFlowShapeContributesToStructuralScore() {
        val fingerprint = Fingerprint(
            id = "test.controlFlow",
            returnType = "Z",
            parameterTypes = listOf("I"),
            instructionCount = 6,
            registerCount = 2,
            opcodeHistogram = mapOf("IF_EQZ" to 1, "RETURN" to 1),
            branchCount = 1,
            returnCount = 1,
            throwCount = 0
        )
        val matching = MethodIndex(
            definingClass = "Lexample/Match;",
            name = "a",
            returnType = "Z",
            parameterTypes = listOf("I"),
            accessFlags = 1,
            instructionCount = 6,
            registerCount = 2,
            opcodeHistogram = mapOf("IF_EQZ" to 1, "RETURN" to 1),
            branchCount = 1,
            returnCount = 1,
            throwCount = 0
        )
        val divergent = matching.copy(
            definingClass = "Lexample/Divergent;",
            branchCount = 0,
            returnCount = 3,
            throwCount = 1
        )

        val matchingScore = FingerprintMatcher.score(matching, fingerprint)
        val divergentScore = FingerprintMatcher.score(divergent, fingerprint)

        assertTrue(matchingScore > divergentScore)
        assertEquals(1.0, matchingScore)
    }

    @Test
    fun ambiguousStructuralCandidatesRequireReview() {
        val fp = Fingerprint(
            id = "test.ambiguous",
            returnType = "Z",
            parameterTypes = listOf("I"),
            instructionCount = 4,
            registerCount = 3,
            opcodeHistogram = mapOf("RETURN" to 2)
        )
        val methods = listOf(
            MethodIndex("Lone/A;", "x", "Z", listOf("I"), 1, 4, 3, mapOf("RETURN" to 2)),
            MethodIndex("Lone/B;", "y", "Z", listOf("I"), 1, 4, 3, mapOf("RETURN" to 2))
        )
        val result = FingerprintMatcher.match(
            listOf(DexIndex("classes.dex", 2, 2, emptyList(), methods)),
            listOf(fp)
        ).single()

        assertEquals("REVIEW", result.status)
        assertTrue(result.candidates.size >= 2)
    }

    @Test
    fun missingTargetIsBroken() {
        val result = FingerprintMatcher.match(
            listOf(DexIndex("classes.dex", 0, 0, emptyList(), emptyList())),
            listOf(Fingerprint("missing"))
        ).single()

        assertEquals("BROKEN", result.status)
    }
}
