package app.tca

import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.util.ReferenceUtil
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.zip.ZipFile

data class MethodIndex(
    val definingClass: String,
    val name: String,
    val returnType: String,
    val parameterTypes: List<String>,
    val accessFlags: Int,
    val instructionCount: Int,
    val registerCount: Int,
    val opcodeHistogram: Map<String, Int>,
    val classSuperType: String? = null,
    val classInterfaces: List<String> = emptyList(),
    val callPrototypeHistogram: Map<String, Int> = emptyMap(),
    val callTargetHistogram: Map<String, Int> = emptyMap(),
    val branchCount: Int = 0,
    val returnCount: Int = 0,
    val throwCount: Int = 0
) {
    val signature: String
        get() = definingClass + "->" + name + "(" + parameterTypes.joinToString("") + ")" + returnType
}

data class ClassIndex(
    val type: String,
    val superType: String?,
    val interfaces: List<String>,
    val accessFlags: Int,
    val methodCount: Int,
    val fieldCount: Int
)

data class DexIndex(
    val dexName: String,
    val classCount: Int,
    val methodCount: Int,
    val classes: List<ClassIndex>,
    val methods: List<MethodIndex>
)

object DexIndexer {
    private const val CACHE_VERSION = "1"

    fun indexApkCached(
        apk: File,
        sha256: String,
        apiLevel: Int = 35,
        cacheDir: File = defaultCacheDir()
    ): List<DexIndex> {
        require(apk.isFile) { "APK does not exist: " + apk.absolutePath }
        val cacheFile = File(cacheDir, "$sha256-api$apiLevel-v$CACHE_VERSION.json")
        val mapper = jacksonObjectMapper()
        if (cacheFile.isFile) {
            return runCatching {
                mapper.readValue(
                    cacheFile,
                    mapper.typeFactory.constructCollectionType(List::class.java, DexIndex::class.java)
                )
            }.getOrElse {
                cacheFile.delete()
                buildAndCache(apk, apiLevel, cacheFile, mapper)
            }
        }
        return buildAndCache(apk, apiLevel, cacheFile, mapper)
    }

    private fun buildAndCache(
        apk: File,
        apiLevel: Int,
        cacheFile: File,
        mapper: com.fasterxml.jackson.databind.ObjectMapper
    ): List<DexIndex> {
        val indexes = indexApk(apk, apiLevel)
        runCatching {
            cacheFile.parentFile?.mkdirs()
            val temp = File.createTempFile("tca-index-", ".tmp", cacheFile.parentFile)
            mapper.writeValue(temp, indexes)
            Files.move(
                temp.toPath(),
                cacheFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE
            )
        }
        return indexes
    }

    fun defaultCacheDir(): File =
        File(System.getProperty("user.home"), ".cache/telegram-compatibility-analyzer/index")

    fun indexApk(apk: File, apiLevel: Int = 35): List<DexIndex> {
        require(apk.isFile) { "APK does not exist: " + apk.absolutePath }

        return ZipFile(apk).use { zip ->
            zip.entries().asSequence()
                .filter { it.name.matches(Regex("classes\\d*\\.dex")) }
                .sortedWith(compareBy<java.util.zip.ZipEntry> { dexNumber(it.name) }.thenBy { it.name })
                .map { entry ->
                    val bytes = zip.getInputStream(entry).use { it.readBytes() }
                    indexDex(entry.name, bytes, apiLevel)
                }
                .toList()
        }
    }

    private fun indexDex(name: String, bytes: ByteArray, apiLevel: Int): DexIndex {
        val dexFile = DexBackedDexFile.fromInputStream(Opcodes.forApi(apiLevel), bytes.inputStream())
        val classes = dexFile.classes.toList().sortedBy { it.type }
        val classIndexes = classes.map(::indexClass)
        val classByType = classes.associateBy { it.type }
        val methods = classes.flatMap { it.methods }.map { method ->
            indexMethod(method, classByType)
        }.sortedBy { it.signature }

        return DexIndex(
            dexName = name,
            classCount = classes.size,
            methodCount = methods.size,
            classes = classIndexes,
            methods = methods
        )
    }

    private fun indexClass(classDef: ClassDef): ClassIndex =
        ClassIndex(
            type = classDef.type,
            superType = classDef.superclass,
            interfaces = classDef.interfaces.sorted(),
            accessFlags = classDef.accessFlags,
            methodCount = classDef.methods.count(),
            fieldCount = classDef.fields.count()
        )

    private fun indexMethod(method: Method, classes: Map<String, ClassDef>): MethodIndex {
        val implementation = method.implementation
        val histogram = linkedMapOf<String, Int>()
        var instructionCount = 0
        val callPrototypes = linkedMapOf<String, Int>()
        val callTargets = linkedMapOf<String, Int>()
        var branchCount = 0
        var returnCount = 0
        var throwCount = 0

        implementation?.instructions?.forEach { instruction ->
            instructionCount++
            val opcode = instruction.opcode.name
            histogram[opcode] = (histogram[opcode] ?: 0) + 1
            if (opcode.startsWith("IF_") || opcode == "GOTO" || opcode.startsWith("PACKED_SWITCH") || opcode.startsWith("SPARSE_SWITCH")) branchCount++
            if (opcode.startsWith("RETURN")) returnCount++
            if (opcode == "THROW") throwCount++
            if (instruction is ReferenceInstruction && instruction.reference is MethodReference) {
                val ref = instruction.reference as MethodReference
                val prototype = ReferenceUtil.getMethodDescriptor(ref).substringAfter("->")
                callPrototypes[prototype] = (callPrototypes[prototype] ?: 0) + 1
                val target = ref.definingClass + "->" + ref.name + "(" + ref.parameterTypes.joinToString("") + ")" + ref.returnType
                callTargets[target] = (callTargets[target] ?: 0) + 1
            }
        }

        val classDef = classes[method.definingClass]
            ?: error("Defining class not found: \${method.definingClass}")

        return MethodIndex(
            definingClass = method.definingClass,
            name = method.name,
            returnType = method.returnType,
            parameterTypes = method.parameterTypes.map(CharSequence::toString),
            accessFlags = method.accessFlags,
            instructionCount = instructionCount,
            registerCount = implementation?.registerCount ?: 0,
            opcodeHistogram = histogram.toSortedMap(),
            callPrototypeHistogram = callPrototypes.toSortedMap(),
            callTargetHistogram = callTargets.toSortedMap(),
            branchCount = branchCount,
            returnCount = returnCount,
            throwCount = throwCount,
            classSuperType = classDef.superclass,
            classInterfaces = classDef.interfaces.sorted()
        )
    }

    private fun dexNumber(name: String): Int =
        if (name == "classes.dex") 1
        else Regex("classes(\\d+)\\.dex").matchEntire(name)?.groupValues?.get(1)?.toInt() ?: Int.MAX_VALUE
}
