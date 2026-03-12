#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum tracepoint_id {
    TP_SCHED_SETATTR = 0,
    TP_SCHED_SETSCHEDULER,
    TP_SETPRIORITY,
    TP_IOPRIO_SET,
    TP_CGROUP_ATTACH_TASK,
    TP_CGROUP_RELEASE
};

#define MAP_SIZE 1024
#define MASK (MAP_SIZE - 1)

u32 PRODUCED_KEY = 0;
u32 CONSUMED_KEY = 1;
u64 INIT_META = 0;

// 9 полей
// обязательно дополнять отступом для выравнивания по 16!!!!!!!
struct event{
    u64 timestamp;

    u32 tracepoint_id;

    u32 pid;

    u64 cgroup_id;

    s32 nice_value;

    u32 scheduler_policy;

    u32 which_value;

    u32 who_value;

    u64 padding;
};

struct {
__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
__uint(max_entries, 2);
__type(key, u32);
__type(value, u64); // [0] = produced, [1] = consumed
} meta_map SEC(".maps");

struct {
__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
__uint(max_entries, MAP_SIZE);
__type(key, u32);
__type(value, struct event);
} event_map SEC(".maps");

static void update_event(struct event* event, u32 tracepoint_id, u32 pid, u64 cgroup_id, s32 nice_value, u32 scheduler_policy, u32 which_value, u32 who_value){
    if (event == NULL){
        return;
    }

    event->timestamp = bpf_ktime_get_ns();

    event->tracepoint_id = tracepoint_id;
    event->pid = pid;
    event->cgroup_id = cgroup_id;
    event->nice_value = nice_value;
    event->scheduler_policy = scheduler_policy;
    event->which_value = which_value;
    event->who_value = who_value;
    event->padding = 0;
}

static struct event* get_next_event_slot(void *ctx){

    bpf_map_update_elem(&meta_map, &PRODUCED_KEY, &INIT_META, BPF_NOEXIST);
    bpf_map_update_elem(&meta_map, &CONSUMED_KEY, &INIT_META, BPF_NOEXIST);

    u64 *produced_ptr = bpf_map_lookup_elem(&meta_map, &PRODUCED_KEY);
    u64 *consumed_ptr = bpf_map_lookup_elem(&meta_map, &CONSUMED_KEY);
    
    if (!produced_ptr || !consumed_ptr) {
        return NULL;
    }

    u64 produced = *produced_ptr;
    u64 consumed = *consumed_ptr;

    if (produced - consumed >= MAP_SIZE) {
        bpf_printk("Losing event: buffer full");
        return NULL;
    }

    u32 event_key = produced & MASK;

    struct event *event = bpf_map_lookup_elem(&event_map, &event_key);
    if (!event) {
        struct event empty = {};
        bpf_map_update_elem(&event_map, &event_key, &empty, BPF_ANY);
        event = bpf_map_lookup_elem(&event_map, &event_key);
        if (!event) {
            return NULL;
        }
    }

    return event;
}

static void commit_event(void* ctx){
    u32 key = PRODUCED_KEY;
    u64 *produced_ptr = bpf_map_lookup_elem(&meta_map, &key);
    if (produced_ptr){
        (*produced_ptr)++;
    }
}

SEC("tp/cgroup/cgroup_attach_task")
int BPF_PROG(handle_cgroup_attach, int dst_root, int dst_level, u64 dst_id, int pid){
    
    struct event *event = get_next_event_slot(ctx);
    if (!event) {
        return 0; // Нет места в буфере
    }

    update_event(event, TP_CGROUP_ATTACH_TASK, pid, dst_id,0,0,0,0);
    
    commit_event(ctx);

    return 0;
}

