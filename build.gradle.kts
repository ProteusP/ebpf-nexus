plugins {
    id("java")
    id("application")
}

group = "ebpf-nexus"
version = "1.0-SNAPSHOT"

var mainClassName = "ebpf.nexus.Main"

repositories {
    mavenCentral()
}

dependencies {
    implementation(files("libs/one-nio.jar"))
    implementation("org.slf4j:slf4j-api:2.0.9")
}

application{
    mainClass.set(mainClassName)
}

tasks.register<Jar>("fatJar") {
    archiveBaseName.set("${project.name}-all")
    archiveVersion.set(project.version.toString())

    manifest {
        attributes(
            "Main-Class" to mainClassName
        )
    }

    
    from(sourceSets.main.get().output)

    
    from({
        configurations.runtimeClasspath.get().map { 
            if (it.isDirectory) it else zipTree(it) 
        }
    }) 
        
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    
}
