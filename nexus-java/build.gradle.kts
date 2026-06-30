plugins {
    id("java")
    id("application")
}

group = "ebpf.nexus"
version = "1.0.0"

application {
    mainClass.set("ebpf.nexus.Main")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    implementation(files("src/main/resources/lib/one-nio.jar"))

    implementation("org.slf4j:slf4j-api:2.0.9")
    implementation("org.slf4j:slf4j-simple:2.0.9")

    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")

    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.2")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.15.2")

    implementation("io.prometheus:simpleclient:0.16.0")
    implementation("io.prometheus:simpleclient_hotspot:0.16.0")
    implementation("io.prometheus:simpleclient_httpserver:0.16.0")
}

tasks.withType<JavaCompile> {
    options.compilerArgs.addAll(listOf(
        "--add-exports", "jdk.unsupported/sun.misc=ALL-UNNAMED"
    ))
}

tasks.withType<JavaExec> {
    jvmArgs(
        "--add-opens", "java.base/java.lang=ALL-UNNAMED",
        "--add-opens", "jdk.unsupported/sun.misc=ALL-UNNAMED",
        "-Xmx2g",
        "-Xms512m"
    )

    systemProperty("bpf.object.dir",
        project.rootProject.file("ebpf/build").absolutePath)
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<Copy>("copyBpfObjects") {
    from(project.rootProject.file("ebpf/build"))
    into(layout.buildDirectory.dir("resources/main/bpf"))
    include("*.o")
    dependsOn(":ebpf:buildBpf")
}

tasks.named("processResources") {
    dependsOn("copyBpfObjects")
}

tasks.register<Jar>("fatJar") {
    group = "build"
    description = "Builds a fat JAR with all dependencies included"
    archiveClassifier.set("all")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get()
            .filter { it.name.endsWith("jar") }
            .map { zipTree(it) }
    })

    manifest {
        attributes["Main-Class"] = "ebpf.nexus.Main"
    }
}