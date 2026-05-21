/*
 * sys_enter_ioprio_set.bpf.c - eBPF program for syscalls:sys_enter_ioprio_set.
 *
 * Compile:
 *   clang -O2 -target bpf -g -c sys_enter_ioprio_set.bpf.c -o ../build/sys_enter_ioprio_set.o
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
 * Raw tracepoint: syscalls:sys_enter_ioprio_set
 * args[0] = __syscall_nr
 * args[1] = which  (IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, or IOPRIO_WHO_USER)
 * args[2] = who    (pid, pgid, or uid depending on which)
 * args[3] = ioprio (I/O priority value)
 */
SEC("raw_tracepoint/sys_enter_ioprio_set")
int trace_sys_enter_ioprio_set(struct bpf_raw_tracepoint_args *ctx) {
    struct event evt = {};

    evt.timestamp = bpf_ktime_get_ns();
    evt.tracepoint_id = TP_IOPRIO_SET;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.which_value = (u32) ctx->args[1];
    evt.who_value = (u32) ctx->args[2];

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}