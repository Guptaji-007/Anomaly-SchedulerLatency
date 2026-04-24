/*
 * HEAVY CONTENTION WORKLOAD
 * Purpose: Severe CPU contention - many threads competing
 * Pattern: Frequent large latency spikes, sustained high latency
 * Label: heavy_contention
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void* heavy_contention_thread(void* arg) {
    // Very CPU-intensive loop
    for (int i = 0; i < 20000; i++) {
        volatile double x = 1.5;
        for (int j = 0; j < 50000; j++) {
            x = x * 1.1 + (i % 100) * 0.01;
            if (x > 1e10) x = 1.5;
        }
    }
    return NULL;
}

int main() {
    int num_threads = 16;  // Many threads for severe contention
    pthread_t tids[num_threads];
    
    printf("Starting HEAVY CONTENTION workload (%d threads)...\n", num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, heavy_contention_thread, NULL);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    printf("HEAVY CONTENTION workload completed\n");
    return 0;
}
