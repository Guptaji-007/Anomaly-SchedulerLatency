#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* ===== Target TGID map (set from user space) ===== */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_tgid_map SEC(".maps");

/* ===== Runqueue timestamp map (key = TID) ===== */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} wait_map SEC(".maps");

/* ===== Output event ===== */
struct event {
    __u32 pid;
    __u64 latency_ns;
};

/* ===== Ring buffer ===== */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* ===== Check if task belongs to workload TGID ===== */
static __always_inline int is_target_pid(__u32 pid)
{
    __u32 key = 0;
    __u32 *target_tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    if (!target_tgid)
        return 0;

    struct task_struct *task = bpf_task_from_pid(pid);
    if (!task)
        return 0;

    int match = (task->tgid == *target_tgid);
    bpf_task_release(task);

    return match;
}

/* ===== Wakeup tracepoint ===== */
/* Sleeping -> Runnable */
SEC("tracepoint/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 pid = ctx->pid;

    if (!is_target_pid(pid))
        return 0;

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wait_map, &pid, &ts, BPF_ANY);

    return 0;
}

/* ===== Context switch tracepoint ===== */
SEC("tracepoint/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    /* ========================= */
    /* Case 1: Preemption wait  */
    /* Running -> Runnable      */
    /* ========================= */
    __u32 prev_pid = ctx->prev_pid;
    long prev_state = ctx->prev_state;

    /* prev_state == 0 means TASK_RUNNING */
    if (prev_state == 0 && is_target_pid(prev_pid)) {
        bpf_map_update_elem(&wait_map, &prev_pid, &now, BPF_ANY);
    }

    /* ========================= */
    /* Case 2: Runnable -> Run  */
    /* ========================= */
    __u32 next_pid = ctx->next_pid;

    if (!is_target_pid(next_pid))
        return 0;

    __u64 *start_ts = bpf_map_lookup_elem(&wait_map, &next_pid);
    if (!start_ts)
        return 0;

    __u64 latency = now - *start_ts;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = next_pid;
    e->latency_ns = latency;

    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&wait_map, &next_pid);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
