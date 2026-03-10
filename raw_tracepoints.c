#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event{
    u64 timestamp;
    u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct event));
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} events SEC(".maps");

SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(handle_cgroup, struct cgroup *dst_cgrp, struct task_struct *leader,
		       bool threadgroup)
{
    u32 key = 0;
    struct event *e = bpf_map_lookup_elem(&events, &key);
    if (!e) return 0;
    
    e->timestamp = bpf_ktime_get_ns();
    e->pid = BPF_CORE_READ(leader, pid);
    
    return 0;
}
