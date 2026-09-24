plugins {
    kotlin("jvm")
    application
}

kotlin {
    jvmToolchain(21)
}

application {
    mainClass.set("app.tca.MainKt")
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib")
    implementation("com.android.tools.smali:smali-dexlib2:3.0.10")
    implementation("net.dongliu:apk-parser:2.6.10")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}
