/*
 * cgroup_attach_task.bpf.c - eBPF program for cgroup:cgroup_attach_task.
 *
 * Compile:
 *   clang -O2 -target bpf -g -c cgroup_attach_task.bpf.c -o ../build/cgroup_attach_task.o
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u64);
    __type(value, u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tracked_cgroups SEC(".maps");

/*
 * Raw tracepoint: cgroup:cgroup_attach_task
 *
 * TP_PROTO(struct cgroup *dst_cgrp, const char *path,
 *          struct task_struct *task, bool threadgroup)
 *
 * args[0] = struct cgroup *dst_cgrp
 * args[1] = const char *path
 * args[2] = struct task_struct *task
 * args[3] = bool threadgroup
 */
SEC("raw_tracepoint/cgroup_attach_task")
int trace_cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx) {
    /* Zero is a key for all groups flag */
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u8 *tracked = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
    if (!tracked) {
        u64 zero = 0;
        u8 *trackAll = bpf_map_lookup_elem(&tracked_cgroups, &zero);
        if (!trackAll) return 0;
    }
    struct event evt = {};
    struct task_struct *task = (struct task_struct *)ctx->args[2];
    struct cgroup *cgrp = (struct cgroup *)ctx->args[0];

    evt.timestamp = bpf_ktime_get_ns();
    evt.tracepoint_id = TP_CGROUP_ATTACH_TASK;
    evt.cpu_id = bpf_get_smp_processor_id();

    BPF_CORE_READ_INTO(&evt.pid, task, pid);
    BPF_CORE_READ_INTO(&evt.cgroup_id, cgrp, kn, id);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}