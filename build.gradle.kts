import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    `maven-publish`
    id("org.jetbrains.dokka")
}

group = "dev.sublab"
version = "1.0.0"

repositories {
    mavenLocal()
    mavenCentral()
    maven { url = uri("https://repo.repsy.io/mvn/chrynan/public") } // Kotlin SecureRandom
}

val dokkaVersion: String by project
val commonVersion: String by project
val hashingVersion: String by project
val sr25519Version: String by project
val eddsaVersion: String by project
val web3jCryptoVersion: String by project
val zcashBIP39Version: String by project

dependencies {
    testImplementation(kotlin("test"))
    dokkaHtmlPlugin("org.jetbrains.dokka:kotlin-as-java-plugin:$dokkaVersion")
    implementation("dev.sublab:common-kotlin:$commonVersion")
    implementation("dev.sublab:hashing-kotlin:$hashingVersion")
    implementation("dev.sublab:sr25519-kotlin:$sr25519Version")
    implementation("net.i2p.crypto:eddsa:$eddsaVersion")
    implementation("org.web3j:crypto:$web3jCryptoVersion")
    implementation("cash.z.ecc.android:kotlin-bip39:$zcashBIP39Version")
}

tasks.test {
    useJUnitPlatform()
}

tasks.dokkaHtml.configure {
    outputDirectory.set(projectDir.resolve("reference"))
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

val sourcesJar by tasks.registering(Jar::class) {
    archiveClassifier.set("sources")
    from(sourceSets.main.get().allSource)
}

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            from(components["java"])
            artifact(sourcesJar.get())
        }
    }
}