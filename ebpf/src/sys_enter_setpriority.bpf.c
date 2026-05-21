/*
 * sys_enter_setpriority.bpf.c - eBPF program for syscalls:sys_enter_setpriority.
 *
 * Compile:
 *   clang -O2 -target bpf -g -c sys_enter_setpriority.bpf.c -o ../build/sys_enter_setpriority.o
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
 * Raw tracepoint: syscalls:sys_enter_setpriority
 * args[0] = __syscall_nr
 * args[1] = which   (PRIO_PROCESS, PRIO_PGRP, or PRIO_USER)
 * args[2] = who     (pid, pgid, or uid depending on which)
 * args[3] = niceval (new nice value, -20..19)
 */
SEC("raw_tracepoint/sys_enter_setpriority")
int trace_sys_enter_setpriority(struct bpf_raw_tracepoint_args *ctx) {
    struct event evt = {};

    evt.timestamp = bpf_ktime_get_ns();
    evt.tracepoint_id = TP_SETPRIORITY;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.which_value = (u32) ctx->args[1];
    evt.who_value = (u32) ctx->args[2];
    evt.nice_value = (s32)(u32) ctx->args[3];

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}