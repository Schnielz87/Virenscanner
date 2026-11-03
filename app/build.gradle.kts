plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "de.svs.security"
    compileSdk = 36

    defaultConfig {
        applicationId = "de.svs.security"
        minSdk = 26
        targetSdk = 35
        // Build-Nummer von GitHub Actions -> jede Release-APK hat eine hoehere Version (Update-Funktion)
        // +10: die ersten Versionen (1.0.1/1.0.2) wurden im Repo SVS-APP gebaut -> neue Builds sind immer neuer
        val build = (System.getenv("BUILD_NUMBER") ?: "1").toInt() + 10
        versionCode = build
        versionName = "1.0.$build"
    }

    signingConfigs {
        // Fester Schluessel: jede neue APK installiert sich als Update ueber die alte (Daten bleiben erhalten).
        // Fuer den Play Store spaeter einen eigenen, geheimen Schluessel verwenden.
        create("sideload") {
            storeFile = file("signing/sideload.jks")
            storePassword = "svssecurity"
            keyAlias = "svssecurity"
            keyPassword = "svssecurity"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("sideload")
        }
        debug {
            signingConfig = signingConfigs.getByName("sideload")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.5")
    implementation("androidx.work:work-runtime-ktx:2.9.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
