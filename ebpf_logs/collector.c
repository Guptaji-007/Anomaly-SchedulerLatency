#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_EVENTS 100000

static volatile int exiting = 0;

void sig_handler(int sig) {
    exiting = 1;
}

// ==============================
// MATCH EXACTLY WITH OLD CODE
// ==============================
struct event {
    unsigned int pid;
    unsigned long long latency_ns;
};

// ==============================
// WINDOW STORAGE
// ==============================
double latencies[MAX_EVENTS];
int latency_count = 0;

int switch_count = 0;
int over20 = 0, over50 = 0, over100 = 0;

// ==============================
// CSV FILE
// ==============================
FILE *fp;

// ==============================
// CALLBACK 
// ==============================
static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;

    // Convert nanoseconds from eBPF into microseconds for the CSV
    double lat = (double)e->latency_ns / 1000.0;

    if (latency_count < MAX_EVENTS)
        latencies[latency_count++] = lat;

    switch_count++;

    if (lat > 20) over20++;
    if (lat > 50) over50++;
    if (lat > 100) over100++;

    return 0;
}

// ==============================
// UTIL FUNCTIONS
// ==============================
int cmp(const void *a, const void *b) {
    double d = (*(double*)a - *(double*)b);
    return (d > 0) - (d < 0);
}

double percentile(double *arr, int n, double p) {
    if (n == 0) return 0;
    qsort(arr, n, sizeof(double), cmp);
    int idx = (int)(p * n);
    if (idx >= n) idx = n - 1;
    return arr[idx];
}

// ==============================
// MAIN
// ==============================
int main() {
    signal(SIGINT, sig_handler);

    // 🔹 LIFT MEMORY LOCK LIMITS (From old code)
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    struct bpf_object *obj;
    struct ring_buffer *rb;

    // 🔹 LOAD eBPF OBJECT
    obj = bpf_object__open_file("sl.bpf.o", NULL);
    if (!obj) {
        printf("Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        return 1;
    }

    // 🔹 MISSING PART 1: ATTACH PROGRAMS TO TRACEPOINTS
    struct bpf_program *prog;
    struct bpf_link *link;
    bpf_object__for_each_program(prog, obj) {
        link = bpf_program__attach(prog);
        if (!link) {
            printf("Attach failed\n");
            return 1;
        }
    }

    // 🔹 MISSING PART 2: START WORKLOAD
    pid_t pid = fork();
    if (pid == 0) {
        execl("../workload/workload", "workload", NULL);
        exit(0); // Only reached if execl fails
    }
    printf("Workload PID: %d\n", pid);

    // 🔹 MISSING PART 3: SET TARGET TGID IN MAP
    __u32 key = 0;
    __u32 value = pid;
    int map_fd = bpf_object__find_map_fd_by_name(obj, "target_tgid_map");
    if (map_fd < 0) {
        printf("Target map not found\n");
        return 1;
    }
    bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);

    // 🔹 CREATE RING BUFFER
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        printf("Events map not found\n");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        printf("Failed to create ring buffer\n");
        return 1;
    }

    // ==============================
    // CSV SETUP
    // ==============================
    fp = fopen("dataset.csv", "w");
    fprintf(fp,
        "timestamp,switch_count,avg_latency_us,min_latency_us,max_latency_us,"
        "p95_latency_us,p99_latency_us,stddev_latency_us,"
        "events_over_20us,events_over_50us,events_over_100us\n"
    );

    printf("🚀 Collecting real-time scheduler data...\n");

    time_t window_start = time(NULL);
    int status;

    // ==============================
    // MAIN LOOP
    // ==============================
    while (!exiting) {

        ring_buffer__poll(rb, 100);

        // 🔹 MISSING PART 4: EXIT WHEN WORKLOAD FINISHES
        if (waitpid(pid, &status, WNOHANG) == pid) {
            printf("\nWorkload finished. Exiting.\n");
            break;
        }

        time_t now = time(NULL);

        if (now - window_start >= 1) {
            double avg = 0, mn = 0, mx = 0, p95 = 0, p99 = 0, std = 0;

            if (latency_count > 0) {
                double sum = 0;
                mn = latencies[0];
                mx = latencies[0];

                for (int i = 0; i < latency_count; i++) {
                    sum += latencies[i];
                    if (latencies[i] < mn) mn = latencies[i];
                    if (latencies[i] > mx) mx = latencies[i];
                }

                avg = sum / latency_count;
                p95 = percentile(latencies, latency_count, 0.95);
                p99 = percentile(latencies, latency_count, 0.99);

                double var = 0;
                for (int i = 0; i < latency_count; i++)
                    var += (latencies[i] - avg) * (latencies[i] - avg);

                std = sqrt(var / latency_count);
            }

            fprintf(fp,
                "%ld,%d,%f,%f,%f,%f,%f,%f,%d,%d,%d\n",
                now, switch_count, avg, mn, mx, p95, p99, std, over20, over50, over100
            );
            fflush(fp);

            printf("[%ld] avg=%.2f us | p95=%.2f | events=%d\n",
                   now, avg, p95, switch_count);

            // RESET WINDOW
            latency_count = 0;
            switch_count = 0;
            over20 = over50 = over100 = 0;

            window_start = now;
        }
    }

    printf("Stopping...\n");

    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(fp);

    return 0;
}