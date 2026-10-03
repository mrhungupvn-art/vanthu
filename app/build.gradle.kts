plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "vn.vanthu.app"
    compileSdk = 34
    defaultConfig { applicationId = "vn.vanthu.client"; minSdk = 24; targetSdk = 34; versionCode = 2; versionName = "1.1" }
    // Keystore cố định: mọi lần build đều cùng chữ ký nên cài đè được
    signingConfigs {
        getByName("debug") {
            storeFile = rootProject.file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
    }
    buildTypes { release { isMinifyEnabled = false } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
