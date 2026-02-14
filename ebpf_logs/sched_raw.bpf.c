#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    __u64 ts;
    __u32 pid;
    __u32 type;
};

/* ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

/* store target TGID */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_tgid_map SEC(".maps");

/* check if current task belongs to workload */
static __always_inline int is_target()
{
    __u32 key = 0;
    __u32 *tgid = bpf_map_lookup_elem(&target_tgid_map, &key);
    if (!tgid)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    __u32 current_tgid = id >> 32;

    return current_tgid == *tgid;
}

SEC("tracepoint/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    if (!is_target())
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    e->pid = ctx->pid;
    e->type = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
    if (!is_target())
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    e->pid = ctx->next_pid;
    e->type = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
