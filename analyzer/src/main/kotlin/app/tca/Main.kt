package app.tca

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.io.File

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("telegram-compatibility-analyzer")
        println("Usage:")
        println("  analyzer <telegram.apk> [fingerprints.json]")
        println("  analyzer --diff <old.apk> <new.apk> [output-dir]")
        return
    }

    if (args.first() == "--diff") {
        require(args.size >= 3) { "Usage: analyzer --diff <old.apk> <new.apk>" }
        val oldMetadata = ApkIntake.inspect(args[1])
        val newMetadata = ApkIntake.inspect(args[2])
        val oldIndex = DexIndexer.indexApkCached(File(args[1]), oldMetadata.sha256)
        val newIndex = DexIndexer.indexApkCached(File(args[2]), newMetadata.sha256)
        val report = DifferentialAnalyzer.compare(oldMetadata, newMetadata, oldIndex, newIndex)
        val json = jacksonObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(report)
        val outputDir = args.getOrNull(3)?.let(::File)
        if (outputDir != null) {
            outputDir.mkdirs()
            File(outputDir, "differential-report.json").writeText(json)
            File(outputDir, "differential-summary.md").writeText(
                buildString {
                    appendLine("# Telegram Compatibility Differential Report")
                    appendLine()
                    appendLine("## APKs")
                    appendLine()
                    appendLine("- Old: ${oldMetadata.versionName} (${oldMetadata.versionCode})")
                    appendLine("- New: ${newMetadata.versionName} (${newMetadata.versionCode})")
                    appendLine("- Old SHA-256: ${oldMetadata.sha256}")
                    appendLine("- New SHA-256: ${newMetadata.sha256}")
                    appendLine()
                    appendLine("## Summary")
                    appendLine()
                    report.summary.forEach { (key, value) -> appendLine("- **$key:** $value") }
                    appendLine()
                    appendLine("## Evidence breakdown")\n                    appendLine()\n                    appendLine("Each candidate exposes weighted evidence contributions: structural, class context, call context, and neighborhood.")\n                    appendLine()\n                    appendLine("## Migrations")
                    appendLine()
                    report.migrations.take(200).forEach {
                        appendLine("- ${it.status} (${"%.4f".format(java.util.Locale.ROOT, it.confidence)}): ${it.oldSignature} -> ${it.newSignature ?: "review/broken"}")\n                        it.candidates.firstOrNull()?.let { candidate ->\n                            val e = candidate.evidence\n                            appendLine("  - Evidence: structural=${"%.4f".format(java.util.Locale.ROOT, e.structural)}, class=${"%.4f".format(java.util.Locale.ROOT, e.classContext)}, call=${"%.4f".format(java.util.Locale.ROOT, e.callContext)}, neighborhood=${"%.4f".format(java.util.Locale.ROOT, e.neighborhood)}")\n                        }
                    }
                }
            )
        }
        println(json)
        return
    }

    val apkPath = args[0]

    val apkFile = File(apkPath)
    val metadata = ApkIntake.inspect(apkPath)
    val dexIndexes = DexIndexer.indexApkCached(apkFile, metadata.sha256)

    val fingerprintPath = args.getOrNull(1)
    val fingerprintSet = if (fingerprintPath != null) {
        FingerprintLoader.load(File(fingerprintPath))
    } else {
        val resource = object {}.javaClass.classLoader.getResourceAsStream("fingerprints.json")
            ?: error("Bundled fingerprints.json not found")
        resource.use { FingerprintLoader.loadJson(it.reader().readText()) }
    }

    val matches = FingerprintMatcher.match(dexIndexes, fingerprintSet.fingerprints)
    val summaryStatus = when {
        matches.any { it.status == "BROKEN" } -> "BROKEN"
        matches.any { it.status == "REVIEW" } -> "REVIEW"
        else -> "PASS"
    }

    val report = mapOf(
        "schemaVersion" to "1",
        "apk" to mapOf(
            "path" to metadata.path,
            "packageName" to metadata.packageName,
            "versionName" to metadata.versionName,
            "versionCode" to metadata.versionCode,
            "sha256" to metadata.sha256,
            "dexCount" to metadata.dexEntries.size
        ),
        "summary" to mapOf(
            "status" to summaryStatus,
            "exactMatches" to matches.count { it.status == "EXACT" },
            "migratedMatches" to matches.count { it.status == "MIGRATED" },
            "reviewMatches" to matches.count { it.status == "REVIEW" },
            "brokenMatches" to matches.count { it.status == "BROKEN" }
        ),
        "fingerprints" to matches
    )

    println(jacksonObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(report))
}
