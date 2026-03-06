import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

// Load signing config from local.properties (for local builds)
val localProperties = Properties().apply {
    val f = rootProject.file("local.properties")
    if (f.exists()) load(f.inputStream())
}

android {
    namespace = "com.biolink.auth"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.biolink.auth"
        minSdk = 29          // Android 10 – guarantees StrongBox / TEE support
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    signingConfigs {
        create("release") {
            val ksFile = System.getenv("KEYSTORE_PATH")
                ?: localProperties.getProperty("keystore.path")
            val ksPassword = System.getenv("KEYSTORE_PASSWORD")
                ?: localProperties.getProperty("keystore.password")
            val keyAlias = System.getenv("KEY_ALIAS")
                ?: localProperties.getProperty("key.alias")
            val keyPassword = System.getenv("KEY_PASSWORD")
                ?: localProperties.getProperty("key.password")

            if (ksFile != null) {
                storeFile = file(ksFile)
                storePassword = ksPassword
                this.keyAlias = keyAlias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.biometric)
    implementation(libs.ktor.client.android)
    implementation(libs.ktor.client.websockets)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.zxing.core)
    implementation(libs.zxing.android.embedded)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.lifecycle.service)
}
