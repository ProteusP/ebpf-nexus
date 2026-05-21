/*
 * cgroup_release.bpf.c - eBPF program for cgroup:cgroup_release.
 *
 * Compile:
 *   clang -O2 -target bpf -g -c cgroup_release.bpf.c -o ../build/cgroup_release.o
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
} events SEC(".maps");

/*
 * Raw tracepoint: cgroup:cgroup_release
 * args[0] = cgrp_id (cgroup id being released)
 * args[1] = root_id
 *
 */
SEC("raw_tracepoint/cgroup_release")
int trace_cgroup_release(struct bpf_raw_tracepoint_args *ctx) {
    struct event evt = {};

    evt.timestamp = bpf_ktime_get_ns();
    evt.tracepoint_id = TP_CGROUP_RELEASE;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.cgroup_id = ctx->args[0];

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}