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
} events SEC(".maps");

/*
 * Raw tracepoint: cgroup:cgroup_attach_task
 * args[0] = dst_cgrp_id
 * args[1] = pid
 */
SEC("raw_tracepoint/cgroup_attach_task")
int trace_cgroup_attach_task(struct bpf_raw_tracepoint_args *ctx) {
    struct event evt = {};

    evt.timestamp = bpf_ktime_get_ns();
    evt.tracepoint_id = TP_CGROUP_ATTACH_TASK;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32) ctx->args[1];
    evt.cgroup_id = ctx->args[0];

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}