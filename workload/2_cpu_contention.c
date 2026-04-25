/*
 * CPU CONTENTION WORKLOAD
 * Purpose: CPU resource contention among multiple threads
 * Pattern: Spikes when threads compete for CPU cores
 * Label: cpu_contention
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void* cpu_intensive_thread(void* arg) {
    // CPU-bound loop - will cause context switches
    for (int i = 0; i < 5000; i++) {
        volatile int x = 0;
        for (int j = 0; j < 10000; j++) {
            x = x + j * (i % 100);
        }
    }
    return NULL;
}

int main() {
    int num_threads = 8;  // Create more threads than CPU cores
    pthread_t tids[num_threads];
    
    printf("Starting CPU CONTENTION workload (%d threads)...\n", num_threads);
    
    // Create threads - they'll fight for CPU
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, cpu_intensive_thread, NULL);
    }
    
    // Wait for all
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    printf("CPU CONTENTION workload completed\n");
    return 0;
}
