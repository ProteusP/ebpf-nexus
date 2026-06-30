plugins {
    id("java")
}

group = "ebpf.nexus"
version = "1.0.0"

subprojects {
    repositories {
        mavenCentral()
    }
}

tasks.register("buildAll") {
    group = "build"
    description = "Builds Java SDK and eBPF programs"
    dependsOn(":nexus-java:build", ":ebpf:buildBpf")
}

tasks.register("cleanAll") {
    group = "build"
    description = "Cleans all submodules"
    dependsOn(":nexus-java:clean", ":ebpf:cleanBpf")
}

val distributionDir = layout.buildDirectory.dir("dist")

// Copy eBPF objects into distribution
tasks.register<Copy>("copyBpfObjects") {
    from("ebpf/build")
    into(distributionDir.map { it.dir("ebpf") })
    include("*.o")
    dependsOn(":ebpf:buildBpf")
}

// Copy fat JAR into distribution
tasks.register<Copy>("copyFatJar") {
    from("nexus-java/build/libs")
    into(distributionDir)
    include("*-all.jar")
    dependsOn(":nexus-java:fatJar")
}

// Assemble complete distribution
tasks.register("assembleDist") {
    group = "distribution"
    description = "Creates complete distribution with JAR, eBPF objects, and run script"
    dependsOn("copyBpfObjects", "copyFatJar")
}

// Create a tarball of the distribution
tasks.register<Tar>("distTar") {
    group = "distribution"
    description = "Creates a tarball of the full distribution"
    dependsOn("assembleDist")
    compression = Compression.GZIP
    archiveFileName.set("nexus-${project.version}.tar.gz")
    from(distributionDir)
}