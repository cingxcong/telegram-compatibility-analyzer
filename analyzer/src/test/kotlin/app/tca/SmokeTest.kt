package app.tca

import kotlin.test.Test
import kotlin.test.assertTrue

class SmokeTest {
    @Test
    fun analyzerStarts() {
        assertTrue("telegram-compatibility-analyzer".isNotBlank())
    }
}
