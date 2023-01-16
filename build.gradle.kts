import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm")
    kotlin("plugin.serialization")
    id("org.jetbrains.dokka")
    id("io.github.gradle-nexus.publish-plugin")
    `maven-publish`
    signing
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
    dokkaJavadocPlugin("org.jetbrains.dokka:kotlin-as-java-plugin:$dokkaVersion")
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

val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    dependsOn("dokkaJavadoc")
    from("$buildDir/dokka/javadoc")
}

tasks.javadoc {
    if (JavaVersion.current().isJava9Compatible) {
        (options as StandardJavadocDocletOptions).addBooleanOption("html5", true)
    }
}

publishing {
    publications {
        register("mavenJava", MavenPublication::class) {
            groupId = groupId
            artifactId = rootProject.name
            version = version

            from(components["java"])
            artifact(sourcesJar.get())
            artifact(javadocJar.get())

            pom {
                name.set(rootProject.name)
                description.set("Sublab's Common Kotlin library")
                url.set("https://github.com/sublabdev/${rootProject.name}")
                licenses {
                    license {
                        name.set("Apache 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        name.set("Sublab")
                        email.set("info@sublab.dev")
                        organization.set("Substrate Laboratory LLC")
                        organizationUrl.set("https://sublab.dev")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/sublabdev/${rootProject.name}.git")
                    developerConnection.set("scm:git:https://github.com/sublabdev/${rootProject.name}.git")
                    url.set("https://github.com/sublabdev/${rootProject.name}")
                }
            }
        }
    }
}

nexusPublishing {
    repositories {
        sonatype {
            packageGroup.set("dev.sublab")
            username.set(extra.get("ossrhUsername") as? String)
            password.set(extra.get("ossrhPassword") as? String)
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

signing {
    useGpgCmd()
    sign(publishing.publications["mavenJava"])
}