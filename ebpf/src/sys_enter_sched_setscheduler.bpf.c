/*
 * sys_enter_sched_setscheduler.bpf.c - eBPF program for syscalls:sys_enter_sched_setscheduler.
 *
 * Compile:
 *   clang -O2 -target bpf -g -c sys_enter_sched_setscheduler.bpf.c -o ../build/sys_entersched_setscheduler.o
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
 * Raw tracepoint: syscalls:sys_enter_sched_setscheduler
 * args[0] = __syscall_nr
 * args[1] = pid
 * args[2] = policy
 * args[3] = param (struct sched_param *)
 */
SEC("raw_tracepoint/sys_enter_sched_setscheduler")
int trace_sys_enter_sched_setscheduler(struct bpf_raw_tracepoint_args *ctx) {
    struct event evt = {};

    evt.timestamp = bpf_ktime_get_ns();
    evt.tracepoint_id = TP_SCHED_SETSCHEDULER;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32) ctx->args[1];
    evt.scheduler_policy = (u32) ctx->args[2];

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}