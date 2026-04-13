#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <limits.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_EVENTS 100000

static volatile int exiting = 0;
static FILE *events_fp = NULL;
static int active_label = 0;

static int get_exe_dir(char *buf, size_t size) {
    ssize_t n = readlink("/proc/self/exe", buf, size - 1);
    if (n <= 0 || (size_t)n >= size) {
        return -1;
    }

    buf[n] = '\0';
    char *slash = strrchr(buf, '/');
    if (!slash) {
        return -1;
    }
    *slash = '\0';
    return 0;
}

static void build_path(char *out, size_t size, const char *dir, const char *file) {
    if (!dir || dir[0] == '\0') {
        snprintf(out, size, "%s", file);
        return;
    }
    snprintf(out, size, "%s/%s", dir, file);
}

static int resolve_bpf_obj_path(char *out, size_t size, const char *exe_dir) {
    const char *env_obj = getenv("SL_BPF_OBJ");
    if (env_obj && env_obj[0] != '\0' && access(env_obj, R_OK) == 0) {
        snprintf(out, size, "%s", env_obj);
        return 0;
    }

    if (access("sl.bpf.o", R_OK) == 0) {
        snprintf(out, size, "sl.bpf.o");
        return 0;
    }

    if (access("ebpf_logs/sl.bpf.o", R_OK) == 0) {
        snprintf(out, size, "ebpf_logs/sl.bpf.o");
        return 0;
    }

    if (exe_dir && exe_dir[0] != '\0') {
        char candidate[PATH_MAX];
        build_path(candidate, sizeof(candidate), exe_dir, "sl.bpf.o");
        if (access(candidate, R_OK) == 0) {
            snprintf(out, size, "%s", candidate);
            return 0;
        }
    }

    return -1;
}

void sig_handler(int sig) { 
    exiting = 1;
    printf("\n⚠️  Received signal - stopping collector...\n");
}

struct event {
    unsigned int pid;
    unsigned int tgid;
    unsigned long long latency_ns;
    unsigned long long ts_ns;
    unsigned int cpu_id;
    int priority;
    char comm[16];
};

struct config {
    unsigned long long min_latency_ns;
    unsigned int sample_rate;
    unsigned int include_kernel_threads;
};

double latencies[MAX_EVENTS];
int priorities[MAX_EVENTS];
int latency_count = 0;
int switch_count = 0;
int over20 = 0, over50 = 0, over100 = 0;

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;
    double lat = (double)e->latency_ns / 1000.0; // Convert to microseconds

    if (events_fp) {
        fprintf(events_fp, "%llu,%u,%u,%s,%u,%d,%.3f,%d\n",
                e->ts_ns,
                e->pid,
                e->tgid,
                e->comm,
                e->cpu_id,
                e->priority,
                lat,
                active_label);
    }

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
    if (argc < 2 || argc > 5) {
        printf("Usage: %s <label: 0|1> [target_tgid] [min_latency_us] [sample_rate]\n", argv[0]);
        printf("  target_tgid: optional, 0 (or omitted) monitors all processes\n");
        printf("  min_latency_us: optional minimum latency to emit (default depends on mode)\n");
        printf("  sample_rate: optional emit 1 out of N matched events (default depends on mode)\n");
        return 1;
    }
    int label = atoi(argv[1]);
    active_label = label;
    __u32 filter_tgid = 0;
    unsigned int min_latency_us = 0;
    unsigned int sample_rate = 1;

    if (argc == 3) {
        filter_tgid = (__u32)atoi(argv[2]);
    } else if (argc >= 4) {
        filter_tgid = (__u32)atoi(argv[2]);
        min_latency_us = (unsigned int)atoi(argv[3]);
        if (argc >= 5) {
            sample_rate = (unsigned int)atoi(argv[4]);
        }
    }

    // Safe defaults to prevent overload in all-process mode.
    if (filter_tgid == 0) {
        if (argc < 4) {
            min_latency_us = 50;
        }
        if (argc < 5 || sample_rate == 0) {
            sample_rate = 10;
        }
    } else {
        if (argc < 4) {
            min_latency_us = 0;
        }
        if (argc < 5 || sample_rate == 0) {
            sample_rate = 1;
        }
    }

    if (sample_rate == 0) {
        sample_rate = 1;
    }

    char exe_dir[PATH_MAX] = {0};
    if (get_exe_dir(exe_dir, sizeof(exe_dir)) != 0) {
        snprintf(exe_dir, sizeof(exe_dir), ".");
    }

    char bpf_obj_path[PATH_MAX] = {0};
    if (resolve_bpf_obj_path(bpf_obj_path, sizeof(bpf_obj_path), exe_dir) != 0) {
        fprintf(stderr, "Failed to locate sl.bpf.o. Build it first or set SL_BPF_OBJ.\n");
        return 1;
    }

    char events_path[PATH_MAX] = {0};
    char dataset_path[PATH_MAX] = {0};
    build_path(events_path, sizeof(events_path), exe_dir, "ebpf_events.csv");
    build_path(dataset_path, sizeof(dataset_path), exe_dir, "dataset.csv");

    signal(SIGINT, sig_handler);
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &r);

    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object from %s\n", bpf_obj_path);
        return 1;
    }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }

    __u32 key = 0, value = filter_tgid;
    int tgid_map_fd = bpf_object__find_map_fd_by_name(obj, "target_tgid_map");
    if (tgid_map_fd < 0 || bpf_map_update_elem(tgid_map_fd, &key, &value, BPF_ANY) != 0) {
        perror("Failed to configure target_tgid_map");
        bpf_object__close(obj);
        return 1;
    }

    struct config cfg = {
        .min_latency_ns = (unsigned long long)min_latency_us * 1000ULL,
        .sample_rate = sample_rate,
        .include_kernel_threads = (filter_tgid != 0) ? 1u : 0u,
    };
    int cfg_map_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    if (cfg_map_fd < 0 || bpf_map_update_elem(cfg_map_fd, &key, &cfg, BPF_ANY) != 0) {
        perror("Failed to configure config_map");
        bpf_object__close(obj);
        return 1;
    }

    int events_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    struct ring_buffer *rb = ring_buffer__new(events_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        perror("Failed to create ring buffer");
        bpf_object__close(obj);
        return 1;
    }

    events_fp = fopen(events_path, "a");
    if (!events_fp) {
        perror("Failed to open ebpf_events.csv");
        ring_buffer__free(rb);
        bpf_object__close(obj);
        return 1;
    }
    fseek(events_fp, 0, SEEK_END);
    if (ftell(events_fp) == 0) {
        fprintf(events_fp, "timestamp_ns,pid,tgid,comm,cpu_id,priority,latency_us,label\n");
    }

    // Open dataset in APPEND mode so we can combine Normal and Anomaly data
    FILE *fp = fopen(dataset_path, "a");
    if (!fp) {
        perror("Failed to open dataset.csv");
        fclose(events_fp);
        ring_buffer__free(rb);
        bpf_object__close(obj);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        fprintf(fp, "timestamp,switch_count,avg_lat,min_lat,max_lat,p95_lat,p99_lat,stddev_lat,over20,over50,over100,avg_prio,highest_prio,label,target_tgid\n");
    }

    printf("🚀 Collecting eBPF scheduler events (Label: %d)...\n", label);
    if (filter_tgid == 0) {
        printf("   Mode: monitor all processes\n");
    } else {
        printf("   Mode: monitor target TGID %u only\n", filter_tgid);
    }
    printf("   Filters: min_latency_us=%u, sample_rate=1/%u\n", min_latency_us, sample_rate);
    printf("   BPF object: %s\n", bpf_obj_path);
    printf("   Per-event log: %s\n", events_path);
    printf("   Window stats: %s\n", dataset_path);
    printf("   Press Ctrl+C to stop\n");
    time_t window_start = time(NULL);

    while (!exiting) {
        ring_buffer__poll(rb, 100);

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

                fprintf(fp, "%ld,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%.1f,%d,%d,%u\n",
                        now, switch_count, avg, mn, mx, p95, p99, sqrt(var/latency_count),
                        over20, over50, over100, sum_prio/latency_count, highest_prio, label, filter_tgid);
                fflush(fp);
            }

            fflush(events_fp);
            latency_count = 0;
            switch_count = 0;
            over20 = 0;
            over50 = 0;
            over100 = 0;
            window_start = now;
        }
    }

    if (latency_count > 0) {
        time_t now = time(NULL);
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

        fprintf(fp, "%ld,%d,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%d,%d,%d,%.1f,%d,%d,%u\n",
                now, switch_count, avg, mn, mx, p95, p99, sqrt(var/latency_count),
                over20, over50, over100, sum_prio/latency_count, highest_prio, label, filter_tgid);
        fflush(fp);
    }

    if (events_fp) {
        fflush(events_fp);
    }

    printf("✓ Stopped collecting events\n");
    printf("✓ Collector shutdown complete\n");

    if (events_fp) {
        fclose(events_fp);
        events_fp = NULL;
    }
    ring_buffer__free(rb);
    bpf_object__close(obj);
    fclose(fp);
    return 0;
}