package app.tca

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.io.File

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        println("telegram-compatibility-analyzer")
        println("Usage:")
        println("  analyzer <telegram.apk> [fingerprints.json]")
        println("  analyzer --diff <old.apk> <new.apk>")
        return
    }

    if (args.first() == "--diff") {
        require(args.size >= 3) { "Usage: analyzer --diff <old.apk> <new.apk>" }
        val oldMetadata = ApkIntake.inspect(args[1])
        val newMetadata = ApkIntake.inspect(args[2])
        val oldIndex = DexIndexer.indexApk(File(args[1]))
        val newIndex = DexIndexer.indexApk(File(args[2]))
        val report = DifferentialAnalyzer.compare(oldMetadata, newMetadata, oldIndex, newIndex)
        println(jacksonObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(report))
        return
    }

    val apkPath = args[0]

    val apkFile = File(apkPath)
    val metadata = ApkIntake.inspect(apkPath)
    val dexIndexes = DexIndexer.indexApk(apkFile)

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
