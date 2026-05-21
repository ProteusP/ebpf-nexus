/*
 * sys_enter_sched_setattr.bpf.c - eBPF program for syscalls:sys_enter_sched_setattr.
 *
 * Compile:
 *   clang -O2 -target bpf -g -c sys_enter_sched_setattr.bpf.c -o ../build/sys_enter_sched_setattr.o
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
 * Raw tracepoint: syscalls:sys_enter_sched_setattr
 * args[0] = __syscall_nr
 * args[1] = pid
 * args[2] = struct sched_attr *attr
 * args[3] = flags
 */
SEC("raw_tracepoint/sys_enter_sched_setattr")
int trace_sys_enter_sched_setattr(struct bpf_raw_tracepoint_args *ctx) {
    struct event evt = {};
    struct sched_attr *attr = (struct sched_attr *) ctx->args[2];

    evt.timestamp = bpf_ktime_get_ns();
    evt.tracepoint_id = TP_SCHED_SETATTR;
    evt.cpu_id = bpf_get_smp_processor_id();
    evt.pid = (u32) ctx->args[1];

    if (attr) {
        BPF_CORE_READ_INTO(&evt.nice_value, attr, sched_nice);
        BPF_CORE_READ_INTO(&evt.scheduler_policy, attr, sched_policy);
    }

    evt.which_value = (u32) ctx->args[3];

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}