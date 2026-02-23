#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/wait.h>

/* ===== Event structure ===== */
struct event {
    unsigned int pid;
    unsigned long long latency_ns;
};

/* ===== Ring buffer callback ===== */
static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;

    printf("PID %u latency %.2f us\n",
           e->pid,
           e->latency_ns / 1000.0);

    return 0;
}

int main()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    setvbuf(stdout, NULL, _IONBF, 0);

    /* ===== Open BPF object ===== */
    struct bpf_object *obj =
        bpf_object__open_file("sl.bpf.o", NULL);

    if (!obj) {
        printf("Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        return 1;
    }

    /* ===== Attach programs ===== */
    struct bpf_program *prog;
    struct bpf_link *link;

    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (!link) {
            printf("Attach failed\n");
            return 1;
        }
    }

    /* ===== Start workload ===== */
    pid_t pid = fork();

    if (pid == 0) {
        execl("./workload", "workload", NULL);
        exit(0);
    }

    printf("Workload PID: %d\n", pid);

    /* ===== Set target TGID ===== */
    __u32 key = 0;
    __u32 value = pid;

    int map_fd = bpf_object__find_map_fd_by_name(obj, "target_tgid_map");

    if (map_fd < 0) {
        printf("Map not found\n");
        return 1;
    }

    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    /* ===== Create ring buffer ===== */
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");

    struct ring_buffer *rb =
        ring_buffer__new(map_fd, handle_event, NULL, NULL);

    if (!rb) {
        printf("Ring buffer failed\n");
        return 1;
    }

    /* ===== Poll events ===== */
    int status;
    while (1) {
        ring_buffer__poll(rb, 100);

        if (waitpid(pid, &status, WNOHANG) == pid)
            break;
    }

    printf("Workload finished\n");
    return 0;
}
