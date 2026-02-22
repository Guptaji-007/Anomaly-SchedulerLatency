#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <sys/wait.h>


struct event {
    unsigned int pid;
    unsigned long long latency_ns;
};


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


    struct bpf_object *obj;

    obj = bpf_object__open_file("sl.bpf.o", NULL);

    if (!obj)
    {
        printf("open failed\n");
        return 1;
    }


    if (bpf_object__load(obj))
    {
        printf("load failed\n");
        return 1;
    }



    /* attach programs */
    struct bpf_program *prog;

    bpf_object__for_each_program(prog, obj)
        bpf_program__attach(prog);



    /* start workload */
    pid_t pid = fork();


    if (pid == 0)
    {
        execl("./workload", "workload", NULL);

        exit(0);
    }


    printf("Workload PID: %d\n", pid);



    /* update target map */
    __u32 key = 0;

    __u32 value = pid;


    int map_fd;

    map_fd = bpf_object__find_map_fd_by_name(obj,
                                             "target_tgid_map");


    bpf_map_update_elem(map_fd,
                        &key,
                        &value,
                        BPF_ANY);



    /* ring buffer */
    struct ring_buffer *rb;

    map_fd = bpf_object__find_map_fd_by_name(obj,
                                             "events");


    rb = ring_buffer__new(map_fd,
                          handle_event,
                          NULL,
                          NULL);



    int status;



    while (1)
    {
        ring_buffer__poll(rb, 100);

        if (waitpid(pid, &status, WNOHANG) == pid)
            break;
    }



    return 0;    obj = bpf_object__open_file("sched_latency.bpf.o", NULL);

}

