/*
 * common.h - Shared definitions for all eBPF tracepoint programs.
 *
 * Contains the event structure sent to userspace and tracepoint
 * identifiers used by both the eBPF programs and the Java SDK.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/* Tracepoint identifiers - must match the Java Event.tp_id values. */
enum tracepoint_id {
    TP_SCHED_SETATTR       = 0,
    TP_SCHED_SETSCHEDULER  = 1,
    TP_SETPRIORITY         = 2,
    TP_IOPRIO_SET          = 3,
    TP_CGROUP_ATTACH_TASK  = 4,
    TP_CGROUP_RELEASE      = 5,
};

/*
 * Event payload sent to userspace via the perf event array map.
 *
 * Fields are ordered by decreasing alignment (u64 first, then u32)
 * to avoid implicit compiler padding.
 *
 * Total size: 48 bytes (no padding at the end).
 */
struct event {
    u64 timestamp;          /* nanoseconds since boot (bpf_ktime_get_ns) */
    u32 tracepoint_id;      /* enum tracepoint_id */
    u32 cpu_id;             /* CPU that generated the event */
    u32 pid;                /* process id */
    /* 4 bytes implicit padding */
    u64 cgroup_id;          /* cgroup identifier */
    s32 nice_value;         /* niceness value (-20..19) */
    u32 scheduler_policy;   /* SCHED_NORMAL, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE */
    u32 which_value;        /* generic 'which' argument (PRIO_PROCESS, PRIO_PGRP, PRIO_USER, IOPRIO_WHO_PROCESS, IOPRIO_WHO_PGRP, IOPRIO_WHO_USER) */
    u32 who_value;          /* generic 'who' argument (pid, pgid, uid depending on which) */
};

#endif /* __COMMON_H__ */