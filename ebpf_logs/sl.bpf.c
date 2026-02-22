#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


/* map: target TGID */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_tgid_map SEC(".maps");


/* wakeup timestamps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} wakeup_map SEC(".maps");


/* output event */
struct event {
    __u32 pid;
    __u64 latency_ns;
};


/* ring buffer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");



/* helper */
/*static __always_inline int is_target(__u32 pid)
{
    __u32 key = 0;

    __u32 *tgid = bpf_map_lookup_elem(&target_tgid_map, &key);

    if (!tgid)
        return 0;

    __u32 current_tgid = pid;

    return current_tgid == *tgid;
}*/

static __always_inline int is_target(__u32 pid)
{
    __u32 key = 0;

    __u32 *target_tgid =
        bpf_map_lookup_elem(&target_tgid_map, &key);

    if (!target_tgid)
        return 0;

    struct task_struct *task =
        bpf_get_current_task_btf();

    if (!task)
        return 0;

    return task->tgid == *target_tgid;
}



/* wakeup */
SEC("tracepoint/sched/sched_wakeup")
int handle_wakeup(struct trace_event_raw_sched_wakeup_template *ctx)
{
    __u32 pid = ctx->pid;
/*
	if (!is_target(pid))
        	return 0;

*/
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&wakeup_map, &pid, &ts, BPF_ANY);

    return 0;
}



/* switch */
SEC("tracepoint/sched/sched_switch")
int handle_switch(struct trace_event_raw_sched_switch *ctx)
{
    __u32 pid = ctx->next_pid;


/*	if (!is_target(pid))
        	return 0;

*/
    __u64 *wakeup_ts;

    wakeup_ts = bpf_map_lookup_elem(&wakeup_map, &pid);

    if (!wakeup_ts)
        return 0;


    __u64 now = bpf_ktime_get_ns();

    __u64 latency = now - *wakeup_ts;


    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

    if (!e)
        return 0;


    e->pid = pid;

    e->latency_ns = latency;


    bpf_ringbuf_submit(e, 0);


    bpf_map_delete_elem(&wakeup_map, &pid);


    return 0;
}


char LICENSE[] SEC("license") = "GPL";
