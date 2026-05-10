#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define PF_KTHREAD 0x00200000

char LICENSE[] SEC("license") = "GPL";
// GPL license allows access to certain privileged helper functions.

/* =================================================
 * MAPS
 * ================================================= */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_tgid_map SEC(".maps");
// Stores a target TGID filter. 

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");
// map for pid -> timestamp when task became runnable

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");
// Ring buffer used to send data to userspace.
struct config {
    u64 min_latency_ns;
    u32 sample_rate;
    u32 include_kernel_threads;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct config);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} sample_counter SEC(".maps");
// per CPU counter for sampling logic

/* =================================================
 * ENRICHED EVENT STRUCTURE
 * ================================================= */
struct event {
    u32 pid;
    u32 tgid;
    u64 latency_ns;
    u64 ts_ns;
    u32 cpu_id;
    int priority;
    char comm[16];
};

/* =================================================
 * TRACEPOINT HOOKS
 * ================================================= */

/* Hook 1: sched_wakeup (For tasks waking from sleep/IO) */
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    u32 tgid = p->tgid;

    // Optional TGID filter: 0 means monitor all tasks
    u32 key = 0;
    u32 *target_tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    if (target_tgid && *target_tgid != 0 && *target_tgid != tgid) {
        return 0;
    }

    u32 pid = p->pid;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}


// when a new task is woken up and added to the runqueue, it triggers sched_wakeup_new.

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    u32 tgid = p->tgid;

    // Optional TGID filter: 0 means monitor all tasks
    u32 key = 0;
    u32 *target_tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    if (target_tgid && *target_tgid != 0 && *target_tgid != tgid) {
        return 0;
    }

    u32 pid = p->pid;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

/* Hook 3: sched_switch (The core latency calculator) */
SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    u64 ts = bpf_ktime_get_ns();

    // Optional TGID filter: 0 means monitor all tasks
    u32 key = 0;
    u32 *target_tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    u32 filter_tgid = target_tgid ? *target_tgid : 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    
    // -----------------------------------------------------------
    // THE FIX: RECORD THE TASK BEING PREEMPTED (if target)
    // If the task leaving the CPU is still in TASK_RUNNING (0), 
    // it was preempted. Record the time it entered the runqueue.
    // -----------------------------------------------------------
    long state = BPF_CORE_READ(prev, __state);

    // state 0 means TASK_RUNNING (the task was preempted, not sleeping)
    if (state == 0) { 
        u32 prev_tgid = prev->tgid;
        if (filter_tgid == 0 || filter_tgid == prev_tgid) {
            u32 prev_pid = prev->pid;
            bpf_map_update_elem(&start, &prev_pid, &ts, BPF_ANY);
        }
    }

    // -----------------------------------------------------------
    // CALCULATE LATENCY FOR TASK GETTING THE CPU
    // -----------------------------------------------------------
    u32 next_pid = next->pid;
    u32 next_tgid = next->tgid;

    if (next_pid == 0 || next_tgid == 0) {
        return 0;
    }

    if (cfg && cfg->include_kernel_threads == 0) {
        unsigned long flags = BPF_CORE_READ(next, flags);
        if (flags & PF_KTHREAD) {
            return 0;
        }
    }

    if (filter_tgid != 0 && filter_tgid != next_tgid) {
        return 0;
    }

    u64 *tsp = bpf_map_lookup_elem(&start, &next_pid);
    if (!tsp) {
        return 0; /* Task start time wasn't recorded */
    }

    u64 latency = ts - *tsp;
    bpf_map_delete_elem(&start, &next_pid);

    if (cfg && latency < cfg->min_latency_ns) {
        return 0;
    }

    if (cfg && cfg->sample_rate > 1) {
        u64 *counter = bpf_map_lookup_elem(&sample_counter, &key);
        if (counter) {
            (*counter)++;
            if ((*counter % cfg->sample_rate) != 0) {
                return 0;
            }
        }
    }

    /* Send Data to User Space via Ring Buffer */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = next_pid;
    e->tgid = next_tgid;
    e->latency_ns = latency;
    e->ts_ns = ts;
    e->cpu_id = bpf_get_smp_processor_id(); 
    e->priority = next->prio; 
    bpf_core_read_str(e->comm, sizeof(e->comm), next->comm);
    // bpf_core_read_str is a helper that safely reads a string from kernel memory.

    bpf_ringbuf_submit(e, 0);
    // sends the event to userspace by submitting it to the ring buffer.
    return 0;
}