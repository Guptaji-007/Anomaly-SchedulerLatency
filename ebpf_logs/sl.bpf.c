#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* =================================================
 * MAPS
 * ================================================= */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} target_tgid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* =================================================
 * ENRICHED EVENT STRUCTURE
 * ================================================= */
struct event {
    u32 pid;
    u64 latency_ns;
    u32 cpu_id;
    int priority;
};

/* =================================================
 * TRACEPOINT HOOKS
 * ================================================= */

/* Hook 1: sched_wakeup (For tasks waking from sleep/IO) */
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    u32 tgid = p->tgid;
    
    // Filter by target workload only
    u32 key = 0;
    u32 *target_tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    if (!target_tgid || *target_tgid != tgid) {
        return 0; // Ignore non-target processes
    }
    
    u32 pid = p->pid;
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    u32 tgid = p->tgid;
    
    // Filter by target workload only
    u32 key = 0;
    u32 *target_tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    if (!target_tgid || *target_tgid != tgid) {
        return 0; // Ignore non-target processes
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
    
    // Get target TGID for filtering
    u32 key = 0;
    u32 *target_tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    if (!target_tgid) {
        return 0;
    }
    
    // -----------------------------------------------------------
    // 🔹 THE FIX: RECORD THE TASK BEING PREEMPTED (if target)
    // If the task leaving the CPU is still in TASK_RUNNING (0), 
    // it was preempted. Record the time it entered the runqueue.
    // -----------------------------------------------------------
    long state = BPF_CORE_READ(prev, __state);
    
    // state 0 means TASK_RUNNING (the task was preempted, not sleeping)
    if (state == 0) { 
        u32 prev_tgid = prev->tgid;
        // Only record preemption of target workload
        if (*target_tgid == prev_tgid) {
            u32 prev_pid = prev->pid;
            bpf_map_update_elem(&start, &prev_pid, &ts, BPF_ANY);
        }
    }

    // -----------------------------------------------------------
    // 🔹 CALCULATE LATENCY FOR TASK GETTING THE CPU
    // -----------------------------------------------------------
    u32 next_pid = next->pid;
    u32 next_tgid = next->tgid;

    // Filter by our target workload TGID
    if (*target_tgid != next_tgid) {
        return 0; // Ignore background system tasks
    }

    u64 *tsp = bpf_map_lookup_elem(&start, &next_pid);
    if (!tsp) {
        return 0; /* Task start time wasn't recorded */
    }

    u64 latency = ts - *tsp;
    bpf_map_delete_elem(&start, &next_pid);

    /* Send Data to User Space via Ring Buffer */
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = next_pid;
    e->latency_ns = latency;
    e->cpu_id = bpf_get_smp_processor_id(); 
    e->priority = next->prio; 

    bpf_ringbuf_submit(e, 0);
    return 0;
}