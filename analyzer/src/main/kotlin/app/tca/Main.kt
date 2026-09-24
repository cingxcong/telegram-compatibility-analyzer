package app.tca

fun main(args: Array<String>) {
    val apkPath = args.firstOrNull()

    if (apkPath == null) {
        println("telegram-compatibility-analyzer")
        println("Usage: analyzer <telegram.apk>")
        return
    }

    val metadata = ApkIntake.inspect(apkPath)
    val dexIndexes = DexIndexer.indexApk(java.io.File(apkPath))

    println("telegram-compatibility-analyzer")
    println("APK: " + metadata.path)
    println("SHA-256: " + metadata.sha256)
    println("Package: " + (metadata.packageName ?: "unknown"))
    println("Version: " + (metadata.versionName ?: "unknown") + " (" + (metadata.versionCode ?: "unknown") + ")")
    println("DEX files: " + metadata.dexEntries.size)
    println("Classes: " + dexIndexes.sumOf { it.classCount })
    println("Methods: " + dexIndexes.sumOf { it.methodCount })
    dexIndexes.forEach {
        println("  " + it.dexName + ": " + it.classCount + " classes, " + it.methodCount + " methods")
    }
}
