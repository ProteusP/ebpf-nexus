plugins {
    id("base")
}

val bpfSourceDir = file("src")
val bpfBuildDir  = file("build")

val bpfObjects = listOf(
    "cgroup_attach_task.bpf.c",
    "cgroup_release.bpf.c",
    "sys_enter.bpf.c"
)

tasks.register("buildBpf") {
    group = "build"
    description = "Compiles eBPF programs using clang"

    inputs.dir(bpfSourceDir)
    outputs.dir(bpfBuildDir)

    val targetArch = System.getProperty("os.arch")  // "aarch64" или "amd64"
    val archFlag = if (targetArch == "aarch64") "__TARGET_ARCH_aarch64"
                else if (targetArch == "amd64") "__TARGET_ARCH_x86_64"
                else throw GradleException("Unsupported architecture: $targetArch")

    doLast {
        bpfBuildDir.mkdirs()

        for (source in bpfObjects) {
            val sourceFile = File(bpfSourceDir, source)
            val objectFile = File(bpfBuildDir, source.replace(".bpf.c", ".o"))

            exec {
                workingDir = bpfSourceDir
                commandLine(
                    "clang",
                    "-O2",
                    "-target", "bpf",
                    "-g",
                    "-I", ".",
                     "-D", archFlag,
                    "-c", sourceFile.name,
                    "-o", objectFile.absolutePath
                )
            }

            println("  BPF  ${source} -> ${objectFile.name}")
        }
    }
}

tasks.register<Delete>("cleanBpf") {
    group = "build"
    delete(bpfBuildDir)
}

tasks.named("build") {
    dependsOn("buildBpf")
}

tasks.named("clean") {
    dependsOn("cleanBpf")
}

tasks.register("checkBpfTools") {
    group = "verification"
    description = "Checks if BPF compilation tools are installed"

    doLast {
        val hasClang = runCatching {
            exec {
                commandLine("clang", "--version")
                isIgnoreExitValue = true
            }.exitValue == 0
        }.getOrDefault(false)

        if (!hasClang) {
            throw GradleException("clang not found. Install clang to compile eBPF programs.")
        }

        val hasLibbpf = File("/usr/include/bpf/bpf_helpers.h").exists()
        if (!hasLibbpf) {
            println("WARNING: libbpf headers not found. Install libbpf-dev.")
        }
    }
}

tasks.named("buildBpf") {
    dependsOn("checkBpfTools")
}