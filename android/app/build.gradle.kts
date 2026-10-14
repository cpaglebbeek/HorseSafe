import com.android.build.api.artifact.SingleArtifact
import groovy.json.JsonSlurper
import java.security.MessageDigest
import java.util.zip.ZipFile

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// ---------------------------------------------------------------------------------------------
// Versie: één bron, ../version.json (repo-root). Dit bestand wordt hier alleen GELEZEN.
// versionCode = major*10000 + minor*100 + patch; minor en patch moeten < 100 blijven,
// anders botst de formule (kritiek 20) en faalt de build.
// ---------------------------------------------------------------------------------------------
val versionJsonFile = rootProject.file("../version.json")
val horseSafeVersion: Map<*, *> = JsonSlurper().parse(versionJsonFile) as Map<*, *>
val horseSafeVersionString: String = horseSafeVersion["version"] as String
val horseSafeCodename: String = horseSafeVersion["codename"] as String
val horseSafeVersionParts: List<Int> = run {
    val m = Regex("""^(\d+)\.(\d+)\.(\d+)$""").matchEntire(horseSafeVersionString)
        ?: throw GradleException("version.json: '$horseSafeVersionString' is geen X.Y.Z")
    m.groupValues.drop(1).map { it.toInt() }
}
val (vMajor, vMinor, vPatch) = horseSafeVersionParts
if (vMinor >= 100 || vPatch >= 100) {
    throw GradleException("version.json: minor en patch moeten < 100 zijn voor versionCode (nu $horseSafeVersionString)")
}
val horseSafeVersionCode: Int = vMajor * 10000 + vMinor * 100 + vPatch

// ---------------------------------------------------------------------------------------------
// Release-ondertekening (R4, HARDWARE_KEYS §11.2.5): eigen keystore op HC55, buiten de repo.
// ~/.keystores/horsesafe.env (HORSESAFE_KS_FILE/_ALIAS/_PASSWORD) komt uit ClaudeSecrets.
// Ontbreekt het bestand (build-box), dan blijft de release ONGETEKEND — nooit stil terugvallen
// op de debug-keystore; verify_apk.sh keurt een ongetekende APK af.
// ---------------------------------------------------------------------------------------------
val releaseSigningEnv: Map<String, String>? = File(System.getProperty("user.home"), ".keystores/horsesafe.env")
    .takeIf { it.isFile }
    ?.readLines()
    ?.mapNotNull { line -> line.split("=", limit = 2).takeIf { it.size == 2 }?.let { it[0].trim() to it[1].trim() } }
    ?.toMap()

// ---------------------------------------------------------------------------------------------
// Vertrouwensankers: de enige bron is ../backend/data. Ze worden bij de build naar
// gegenereerde assets gekopieerd (assets/trust/...), nooit met de hand in android/ gezet (A-22).
// ---------------------------------------------------------------------------------------------
val trustAnchorFiles = listOf(
    rootProject.file("../backend/data/yubico_fido_roots.pem"),
    rootProject.file("../backend/data/aaguids.json"),
)
fun sha256Hex(f: File): String =
    MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }
trustAnchorFiles.forEach { if (!it.isFile) throw GradleException("Vertrouwensanker ontbreekt: $it") }

abstract class CopyTrustAnchorsTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val sources: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        val target = outputDir.get().asFile.resolve("trust")
        outputDir.get().asFile.deleteRecursively()
        target.mkdirs()
        sources.files.forEach { it.copyTo(target.resolve(it.name), overwrite = true) }
    }
}

val copyTrustAnchors = tasks.register<CopyTrustAnchorsTask>("copyTrustAnchors") {
    description = "Kopieert yubico_fido_roots.pem en aaguids.json uit ../backend/data naar gegenereerde assets."
    sources.from(trustAnchorFiles)
}

// ---------------------------------------------------------------------------------------------
// yubikit: SHA-256 van de vier artefacten (3.0.1) vast. Berekend op 2026-10-12 uit de Maven
// Central-download via Gradle. android-aar en fido-jar zijn gekruist met de onafhankelijke
// download in miller-research/yubikit-api/maven (identiek); core en management alleen met de
// SHA-1 die Gradle bij download vastlegde. Bewust GEEN gradle/verification-metadata.xml (kritiek 3).
// ---------------------------------------------------------------------------------------------
val yubikitVersion = libs.versions.yubikit.get()
val yubikitExpectedSha256: Map<String, String> = mapOf(
    "com.yubico.yubikit:android:$yubikitVersion@aar" to "1b975afc4618eefe2d1b3892e7a5805adba806b87d56cfa240e19d36fba31474",
    "com.yubico.yubikit:core:$yubikitVersion@jar" to "99a5e00a2ca2277e43b8747fa8812c80776389ed7a93643c05117ef4fe710a1a",
    "com.yubico.yubikit:fido:$yubikitVersion@jar" to "1223557dafaf688f16602be259ef24272691684ece26e7c94503076725d1641a",
    "com.yubico.yubikit:management:$yubikitVersion@jar" to "a007792363dbaee921782135c6ed4abf52037b7db9c4d5799a72cd618bc53cd7",
)

val yubikitPinned: Configuration = configurations.create("yubikitPinned") {
    isTransitive = false
    isCanBeConsumed = false
    isCanBeResolved = true
}
dependencies {
    yubikitExpectedSha256.keys.forEach { add("yubikitPinned", it) }
}

val verifyYubikitHashes = tasks.register("verifyYubikitHashes") {
    group = "verification"
    description = "Controleert de SHA-256 van de yubikit-artefacten en dat de runtime-classpath precies $yubikitVersion gebruikt."
    inputs.files(yubikitPinned)
    doLast {
        val failures = mutableListOf<String>()
        // 1) Hash per artefact.
        val resolved = yubikitPinned.resolvedConfiguration.resolvedArtifacts
        yubikitExpectedSha256.forEach { (coord, expected) ->
            val name = coord.substringAfter("com.yubico.yubikit:").substringBefore(":")
            val ext = coord.substringAfter("@")
            val art = resolved.firstOrNull { it.moduleVersion.id.name == name && it.extension == ext }
            if (art == null) {
                failures += "$coord: niet gevonden"
            } else {
                val actual = sha256Hex(art.file)
                if (actual != expected) failures += "$coord: sha256 $actual != verwacht $expected"
            }
        }
        // 2) Geen andere yubikit-versie of -module in de runtime-classpaths.
        listOf("debugRuntimeClasspath", "releaseRuntimeClasspath").forEach { cfgName ->
            configurations.getByName(cfgName).incoming.resolutionResult.allComponents.forEach { c ->
                val id = c.moduleVersion ?: return@forEach
                if (id.group == "com.yubico.yubikit") {
                    if (id.version != yubikitVersion) failures += "$cfgName: ${id.group}:${id.name}:${id.version} (verwacht $yubikitVersion)"
                    if (id.name !in setOf("android", "core", "fido", "management")) failures += "$cfgName: onverwachte module ${id.name}"
                }
            }
        }
        if (failures.isNotEmpty()) throw GradleException("verifyYubikitHashes faalt:\n  " + failures.joinToString("\n  "))
        logger.lifecycle("verifyYubikitHashes: 4/4 yubikit-artefacten kloppen ($yubikitVersion)")
    }
}

// ---------------------------------------------------------------------------------------------
// zxing (deel 2, QR-scanner zonder GMS): SHA-256 van de twee artefacten vast, zelfde patroon als
// yubikit. Berekend op 2026-10-14 uit de Maven Central-download en gekruist met de .sha1 die Maven
// Central naast het artefact publiceert (aar 148ce3de…1f28, core-jar 1869da97…e25d: identiek).
// ---------------------------------------------------------------------------------------------
val zxingEmbeddedVersion = libs.versions.zxingEmbedded.get()
val zxingCoreVersion = libs.versions.zxingCore.get()
val zxingExpectedSha256: Map<String, String> = mapOf(
    "com.journeyapps:zxing-android-embedded:$zxingEmbeddedVersion@aar" to "4ab03353127c34e55cbb80fbc9a34031decbcfb1ec5e8f991944d2d494621a33",
    "com.google.zxing:core:$zxingCoreVersion@jar" to "acfa30338c26267b6cab665509c2251bb96e8350bfcad89d59b949ba77011f8d",
)

val zxingPinned: Configuration = configurations.create("zxingPinned") {
    isTransitive = false
    isCanBeConsumed = false
    isCanBeResolved = true
}
dependencies {
    zxingExpectedSha256.keys.forEach { add("zxingPinned", it) }
}

val verifyZxingHashes = tasks.register("verifyZxingHashes") {
    group = "verification"
    description = "Controleert de SHA-256 van de zxing-artefacten en dat de runtime-classpath precies deze versies gebruikt."
    inputs.files(zxingPinned)
    doLast {
        val failures = mutableListOf<String>()
        val resolved = zxingPinned.resolvedConfiguration.resolvedArtifacts
        zxingExpectedSha256.forEach { (coord, expected) ->
            val (group, name) = coord.split(":").let { it[0] to it[1] }
            val ext = coord.substringAfter("@")
            val art = resolved.firstOrNull { it.moduleVersion.id.group == group && it.moduleVersion.id.name == name && it.extension == ext }
            if (art == null) {
                failures += "$coord: niet gevonden"
            } else {
                val actual = sha256Hex(art.file)
                if (actual != expected) failures += "$coord: sha256 $actual != verwacht $expected"
            }
        }
        val expectedVersions = mapOf(
            "com.journeyapps:zxing-android-embedded" to zxingEmbeddedVersion,
            "com.google.zxing:core" to zxingCoreVersion,
        )
        listOf("debugRuntimeClasspath", "releaseRuntimeClasspath").forEach { cfgName ->
            configurations.getByName(cfgName).incoming.resolutionResult.allComponents.forEach { c ->
                val id = c.moduleVersion ?: return@forEach
                if (id.group == "com.journeyapps" || id.group == "com.google.zxing") {
                    val want = expectedVersions["${id.group}:${id.name}"]
                    if (want == null) failures += "$cfgName: onverwachte module ${id.group}:${id.name}"
                    else if (id.version != want) failures += "$cfgName: ${id.group}:${id.name}:${id.version} (verwacht $want)"
                }
            }
        }
        if (failures.isNotEmpty()) throw GradleException("verifyZxingHashes faalt:\n  " + failures.joinToString("\n  "))
        logger.lifecycle("verifyZxingHashes: 2/2 zxing-artefacten kloppen ($zxingEmbeddedVersion, core $zxingCoreVersion)")
    }
}

// ---------------------------------------------------------------------------------------------
// A-13: yubikit logt via slf4j-api (o.a. USB-apparaatnamen en CTAP-debug). Zonder provider is dat
// een NOP-logger. Deze taak laat de build falen zodra een afhankelijkheid een slf4j-provider of een
// oude StaticLoggerBinder binnenhaalt (slf4j-android, logback-android, slf4j-simple, slf4j-nop, ...).
// ---------------------------------------------------------------------------------------------
val forbiddenSlf4jModules = Regex("^(slf4j-(android|simple|nop|jdk14|jdk-platform-logging|log4j12|reload4j|ext)|logback-.*|log4j-slf4j.*|logback-android|tinylog-.*slf4j.*)$")
val slf4jProviderEntries = listOf("META-INF/services/org.slf4j.spi.SLF4JServiceProvider", "org/slf4j/impl/StaticLoggerBinder.class")

val verifyNoSlf4jProvider = tasks.register("verifyNoSlf4jProvider") {
    group = "verification"
    description = "Faalt als releaseRuntimeClasspath (of debug) een slf4j-provider bevat (A-13)."
    doLast {
        val failures = mutableListOf<String>()
        listOf("releaseRuntimeClasspath", "debugRuntimeClasspath").forEach { cfgName ->
            val cfg = configurations.getByName(cfgName)
            cfg.incoming.resolutionResult.allComponents.forEach { c ->
                val id = c.moduleVersion ?: return@forEach
                if (forbiddenSlf4jModules.matches(id.name) || id.group == "ch.qos.logback" || id.group == "com.github.tony19") {
                    failures += "$cfgName: verboden logging-module ${id.group}:${id.name}:${id.version}"
                }
            }
            // Ook de inhoud: een provider kan in een willekeurige jar of AAR zitten.
            val jars = cfg.incoming.artifactView {
                attributes { attribute(Attribute.of("artifactType", String::class.java), "android-classes-jar") }
                lenient(false)
            }.artifacts
            jars.forEach { a ->
                val f = a.file
                if (f.isFile && (f.name.endsWith(".jar"))) {
                    ZipFile(f).use { z ->
                        slf4jProviderEntries.forEach { e ->
                            if (z.getEntry(e) != null) failures += "$cfgName: ${a.id.componentIdentifier.displayName} bevat $e"
                        }
                    }
                }
            }
        }
        if (failures.isNotEmpty()) throw GradleException("verifyNoSlf4jProvider faalt:\n  " + failures.joinToString("\n  "))
        logger.lifecycle("verifyNoSlf4jProvider: geen slf4j-provider in de runtime-classpaths")
    }
}

android {
    namespace = "nl.icthorse.horsesafe"
    compileSdk = 35

    defaultConfig {
        applicationId = "nl.icthorse.horsesafe"
        minSdk = 33
        targetSdk = 35
        versionCode = horseSafeVersionCode
        versionName = "$horseSafeVersionString-$horseSafeCodename"

        buildConfigField("String", "TRUST_ROOTS_SHA256", "\"${sha256Hex(trustAnchorFiles[0])}\"")
        buildConfigField("String", "AAGUIDS_SHA256", "\"${sha256Hex(trustAnchorFiles[1])}\"")
        // Deel 2 (HARDWARE_KEYS §13.9): vaste basis-URL van de device-API. De host staat ook in
        // res/xml/network_security_config.xml (pins); een unit-test bewaakt dat ze gelijk zijn.
        buildConfigField("String", "API_BASE_URL", "\"https://icthorsecloud.nl/HorseSafe/api\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (releaseSigningEnv != null) {
            create("release") {
                storeFile = file(releaseSigningEnv.getValue("HORSESAFE_KS_FILE"))
                storePassword = releaseSigningEnv.getValue("HORSESAFE_KS_PASSWORD")
                keyAlias = releaseSigningEnv.getValue("HORSESAFE_KS_ALIAS")
                keyPassword = releaseSigningEnv.getValue("HORSESAFE_KS_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = signingConfigs.findByName("release")
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    packaging {
        resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" }
    }
}

// Merged release-manifest voor ReleaseManifestTest (JVM): INTERNET, allowBackup, debuggable, intent-filters.
// De unit-tests hangen zo vanzelf af van processReleaseManifest, ook als alleen testDebugUnitTest draait.
val releaseMergedManifest: RegularFileProperty = objects.fileProperty()

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(copyTrustAnchors, CopyTrustAnchorsTask::outputDir)
    }
    onVariants(selector().withBuildType("release")) { variant ->
        releaseMergedManifest.set(variant.artifacts.get(SingleArtifact.MERGED_MANIFEST))
    }
}

tasks.withType<Test>().configureEach {
    val manifest = releaseMergedManifest
    inputs.file(manifest).withPathSensitivity(PathSensitivity.NONE).withPropertyName("releaseMergedManifest")
    jvmArgumentProviders.add(CommandLineArgumentProvider {
        listOf("-Dhorsesafe.releaseManifest=" + manifest.get().asFile.absolutePath)
    })
}

tasks.named("preBuild") { dependsOn(verifyYubikitHashes, verifyZxingHashes, verifyNoSlf4jProvider) }

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.kotlinx.coroutines.android)

    // YubiKey (FIDO2/CTAP2 + Management). Geen slf4j-provider toevoegen (A-13).
    implementation(libs.yubikit.android)
    implementation(libs.yubikit.core)
    implementation(libs.yubikit.fido)
    implementation(libs.yubikit.management)

    // Deel 2: telefoon koppelen. Biometrie alleen BIOMETRIC_STRONG met CryptoObject (biometric/StrongGate);
    // BiometricPrompt vraagt een FragmentActivity. QR-scanner zonder GMS (zxing, hashes gecontroleerd).
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.zxing.android.embedded)
    implementation(libs.zxing.core)

    debugImplementation(libs.androidx.ui.tooling)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
