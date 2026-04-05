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
#include <sys/stat.h>
#include <fcntl.h>

#define MAX_EVENTS 100000

static volatile int exiting = 0;

void sig_handler(int sig) { 
    exiting = 1;
    printf("\n⚠️  Received signal - stopping collector...\n");
    /* Clean up flag file on signal */
    unlink("workload.running");
}

struct event {
    unsigned int pid;
    unsigned long long latency_ns;
    unsigned int cpu_id;
    int priority;
};

double latencies[MAX_EVENTS];
int priorities[MAX_EVENTS];
int latency_count = 0;
int switch_count = 0;
int over20 = 0, over50 = 0, over100 = 0;

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;
    double lat = (double)e->latency_ns / 1000.0; // Convert to microseconds

    if (latency_count < MAX_EVENTS) {
        latencies[latency_count] = lat;
        priorities[latency_count] = e->priority;
        latency_count++;
    }
    switch_count++;

    if (lat > 20) over20++;
    if (lat > 50) over50++;
    if (lat > 100) over100++;
    return 0;
}

int cmp(const void *a, const void *b) {
    double d = (*(double*)a - *(double*)b);
    return (d > 0) - (d < 0);
}

double percentile(double *arr, int n, double p) {
    if (n == 0) return 0;
    qsort(arr, n, sizeof(double), cmp);
    int idx = (int)(p * n);
    return arr[idx >= n ? n - 1 : idx];
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <label: 0 for normal, 1 for anomaly>\n", argv[0]);
        return 1;
    }
    int label = atoi(argv[1]);

    signal(SIGINT, sig_handler);
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    struct bpf_object *obj = bpf_object__open_file("sl.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) {
        printf("Failed to load BPF object\n");
        return 1;
    }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }

    // Start workload and set TGID filter
    pid_t pid = fork();
    if (pid == 0) {
        execl("../workload/workload", "workload", NULL);
        exit(0);
    }

    /* Create flag file to indicate workload is running */
    int flag_fd = open("workload.running", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (flag_fd >= 0) {
        dprintf(flag_fd, "%d\n", pid); /* Write PID for reference */
        close(flag_fd);
    }

    __u32 key = 0, value = pid;
    int tgid_map_fd = bpf_object__find_map_fd_by_name(obj, "target_tgid_map");
    bpf_map_update_elem(tgid_map_fd, &key, &value, BPF_ANY);

    int events_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(events_map_fd, handle_event, NULL, NULL);

    // Open dataset in APPEND mode so we can combine Normal and Anomaly data
    FILE *fp = fopen("dataset.csv", "a");
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        fprintf(fp, "timestamp,switch_count,avg_lat,min_lat,max_lat,p95_lat,p99_lat,stddev_lat,over20,over50,over100,avg_prio,highest_prio,label\n");
    }

    printf("🚀 Collecting windowed data (Label: %d)...\n", label);
    printf("   Target Workload PID: %d\n", pid);
    printf("   Waiting for workload termination...\n");
    time_t window_start = time(NULL);
    int workload_exited = 0;

    while (!exiting && !workload_exited) {
        ring_buffer__poll(rb, 100);
        
        // Check if workload process has terminated
        int status;
        pid_t ret = waitpid(pid, &status, WNOHANG);
        
        if (ret == pid) {
            // Workload process has exited (detected from separate terminal)
            printf("✓ Workload process terminated (PID: %d)\n", pid);
            workload_exited = 1;
            
            // Poll one more time to capture any remaining events
            ring_buffer__poll(rb, 100);
            
            // Flush any remaining data in the current window
            time_t now = time(NULL);
            if (latency_count > 0) {
                double sum = 0, sum_prio = 0;
                double mn = latencies[0], mx = latencies[0];
                int highest_prio = 140;

                for (int i = 0; i < latency_count; i++) {
                    sum += latencies[i];
                    sum_prio += priorities[i];
                    if (latencies[i] < mn) mn = latencies[i];
                    if (latencies[i] > mx) mx = latencies[i];
                    if (priorities[i] < highest_prio) highest_prio = priorities[i];
                }

                double avg = sum / latency_count;
                double p95 = percentile(latencies, latency_count, 0.95);
                double p99 = percentile(latencies, latency_count, 0.99);
                double var = 0;
                for (int i = 0; i < latency_count; i++)
                    var += (latencies[i] - avg) * (latencies[i] - avg);

                fprintf(fp, "%ld,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%.1f,%d,%d\n",
                        now, switch_count, avg, mn, mx, p95, p99, sqrt(var/latency_count),
                        over20, over50, over100, sum_prio/latency_count, highest_prio, label);
                fflush(fp);
                printf("   Final window written to CSV\n");
            }
            break;
        } else if (ret == -1) {
            // Error in waitpid (usually when child already reaped)
            perror("waitpid error");
            break;
        }

        // Normal windowing - write data every 1 second (only if not exiting)
        if (!exiting) {
            time_t now = time(NULL);
            if (now - window_start >= 1) {
                if (latency_count > 0) {
                    double sum = 0, sum_prio = 0;
                    double mn = latencies[0], mx = latencies[0];
                    int highest_prio = 140;

                    for (int i = 0; i < latency_count; i++) {
                        sum += latencies[i];
                        sum_prio += priorities[i];
                        if (latencies[i] < mn) mn = latencies[i];
                        if (latencies[i] > mx) mx = latencies[i];
                        if (priorities[i] < highest_prio) highest_prio = priorities[i];
                    }

                    double avg = sum / latency_count;
                    double p95 = percentile(latencies, latency_count, 0.95);
                    double p99 = percentile(latencies, latency_count, 0.99);
                    double var = 0;
                    for (int i = 0; i < latency_count; i++)
                        var += (latencies[i] - avg) * (latencies[i] - avg);

                    fprintf(fp, "%ld,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%.1f,%d,%d\n",
                            now, switch_count, avg, mn, mx, p95, p99, sqrt(var/latency_count),
                            over20, over50, over100, sum_prio/latency_count, highest_prio, label);
                    fflush(fp);
                }
                // Reset for next window
                latency_count = 0; switch_count = 0; over20 = over50 = over100 = 0;
                window_start = now;
            }
        }
    }

    /* Clean up: Remove flag file to signal workload has stopped */
    unlink("workload.running");
    printf("✓ Stopped collecting events\n");
    printf("✓ Collector shutdown complete\n");

    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(fp);
    return 0;
}