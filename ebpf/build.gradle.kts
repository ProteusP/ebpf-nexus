plugins {
    id("base")
}

val bpfSourceDir = file("src")
val bpfBuildDir  = file("build")

val bpfObjects = listOf(
    "cgroup_attach_task.bpf.c",
    "sys_enter_sched_setattr.bpf.c",
    "sys_enter_sched_setscheduler.bpf.c",
    "sys_enter_setpriority.bpf.c",
    "sys_enter_ioprio_set.bpf.c",
    "cgroup_release.bpf.c"
)

tasks.register("buildBpf") {
    group = "build"
    description = "Compiles eBPF programs using clang"

    inputs.dir(bpfSourceDir)
    outputs.dir(bpfBuildDir)

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