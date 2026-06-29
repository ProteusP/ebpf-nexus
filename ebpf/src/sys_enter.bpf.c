/*
 * syscalls.bpf.c — eBPF program for all tracked syscalls.
 *
 * Compile:
 *   clang -O2 -target bpf -g -c syscalls.bpf.c -o ../build/sys_enter.o
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

#ifdef __TARGET_ARCH_aarch64
#define __NR_sched_setattr      274
#define __NR_sched_setscheduler 119
#define __NR_setpriority        140
#define __NR_ioprio_set         30
#elif defined(__TARGET_ARCH_x86_64)
#define __NR_sched_setattr      314
#define __NR_sched_setscheduler 144
#define __NR_setpriority        141
#define __NR_ioprio_set         251
#else
#error "Define __TARGET_ARCH_aarch64 or __TARGET_ARCH_x86_64 via -D flag"
#endif

/*
 * Tracepoint context for raw_syscalls/sys_enter.
 */
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* Zero is a key for all groups flag */
    u64 cgroup_id = bpf_get_current_cgroup_id();
    u8 *tracked = bpf_map_lookup_elem(&tracked_cgroups, &cgroup_id);
    if (!tracked) {
        u64 zero = 0;
        u8 *trackAll = bpf_map_lookup_elem(&tracked_cgroups, &zero);
        if (!trackAll) return 0;
    }

    long nr = ctx->id;
    struct event evt = {};

    evt.timestamp = bpf_ktime_get_ns();
    evt.cpu_id = bpf_get_smp_processor_id();

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    evt.pid = (__u32)pid_tgid;      /* current pid (thread id) */

    switch (nr) {

    case __NR_sched_setattr: {
        struct sched_attr attr = {};

        evt.tracepoint_id = TP_SCHED_SETATTR;

        if (ctx->args[1]) {
            bpf_probe_read_user(&attr, sizeof(attr),
                                (const void *)ctx->args[1]);

            evt.nice_value       = attr.sched_nice;
            evt.scheduler_policy = attr.sched_policy;
        }

        evt.which_value = (__u32)ctx->args[2];
        break;
    }

    case __NR_sched_setscheduler: {
        struct sched_param param = {};

        evt.tracepoint_id = TP_SCHED_SETSCHEDULER;

        evt.scheduler_policy = (__u32)ctx->args[1];

        if (ctx->args[2]) {
            bpf_probe_read_user(&param, sizeof(param),
                                (const void *)ctx->args[2]);

            evt.nice_value = param.sched_priority;
        }

        break;
    }

    case __NR_setpriority:
        evt.tracepoint_id = TP_SETPRIORITY;

        evt.which_value = (int)ctx->args[0];
        evt.who_value   = (int)ctx->args[1];
        evt.nice_value  = (int)ctx->args[2];
        break;

    case __NR_ioprio_set:
        evt.tracepoint_id = TP_IOPRIO_SET;

        evt.which_value = (__u32)ctx->args[0];
        evt.who_value   = (__u32)ctx->args[1];

        /* // TODO: check
         * ioprio in nice for now
         */
        evt.nice_value = (__s32)ctx->args[2];

        break;

    default:
        return 0;
    }

    bpf_perf_event_output(ctx, &events,
                          BPF_F_CURRENT_CPU,
                          &evt, sizeof(evt));

    return 0;
}