#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/wait.h>

struct event {
    unsigned long long ts;
    unsigned int pid;
    unsigned int type;
};

static int handle_event(void *ctx, void *data, size_t len)
{
    struct event *e = data;
    printf("%llu %u %u\n", e->ts, e->pid, e->type);
    return 0;
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct ring_buffer *rb;
    int map_fd;

    /* open BPF object */
    obj = bpf_object__open_file("sched_raw.bpf.o", NULL);
    if (!obj) {
        printf("Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        return 1;
    }

    /* attach programs */
    bpf_object__for_each_program(prog, obj) {
        if (!bpf_program__attach(prog)) {
            printf("Attach failed\n");
            return 1;
        }
    }

    /* start workload */
    pid_t pid = fork();
    if (pid == 0) {
        execl("./workload", "workload", NULL);
        exit(0);
    }

    printf("Workload TGID: %d\n", pid);

    /* update TGID map */
    __u32 key = 0;
    __u32 value = pid;

    map_fd = bpf_object__find_map_fd_by_name(obj, "target_tgid_map");
    if (map_fd < 0) {
        printf("Map not found\n");
        return 1;
    }

    if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY)) {
        printf("Map update failed\n");
        return 1;
    }

    /* connect ring buffer */
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        printf("Ring buffer failed\n");
        return 1;
    }

    printf("Listening for workload scheduler events...\n");

    int status;

    /* poll until workload exits */
    while (1) {
        ring_buffer__poll(rb, 100);

        if (waitpid(pid, &status, WNOHANG) == pid) {
            printf("Workload finished. Flushing events...\n");
            break;
        }
    }

    /* flush remaining events */
    for (int i = 0; i < 5; i++)
        ring_buffer__poll(rb, 100);

    printf("Logger exiting.\n");

    ring_buffer__free(rb);
    bpf_object__close(obj);

    return 0;
}
