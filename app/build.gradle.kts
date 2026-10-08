plugins { id("com.android.application"); id("org.jetbrains.kotlin.android") }
android {
    namespace = "vn.vanthu.app"
    compileSdk = 34
    defaultConfig { applicationId = "vn.vanthu.client"; minSdk = 24; targetSdk = 34; versionCode = 3; versionName = "1.2" }
    buildTypes { release { isMinifyEnabled = false } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
