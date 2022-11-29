import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.7.21"
    kotlin("plugin.serialization") version "1.7.21"
    `maven-publish`
}

group = "dev.sublab"
version = "1.0.0"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("dev.sublab:common-kotlin:1.0.0")
    implementation("dev.sublab:hashing-kotlin:1.0.0")
    implementation("dev.sublab:sr25519-kotlin:1.0.0")
    implementation("net.i2p.crypto:eddsa:0.3.0")
    implementation("org.web3j:crypto:4.9.5")
    implementation("cash.z.ecc.android:kotlin-bip39:1.0.4")
}

tasks.test {
    useJUnitPlatform()
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