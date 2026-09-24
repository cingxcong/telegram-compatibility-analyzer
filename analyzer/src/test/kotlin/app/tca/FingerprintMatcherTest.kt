package app.tca

import kotlin.test.Test
import kotlin.test.assertEquals

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
            opcodeHistogram = mapOf("RETURN" to 1)
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
    fun missingTargetIsBroken() {
        val result = FingerprintMatcher.match(
            listOf(DexIndex("classes.dex", 0, 0, emptyList(), emptyList())),
            listOf(Fingerprint("missing"))
        ).single()

        assertEquals("BROKEN", result.status)
    }
}
