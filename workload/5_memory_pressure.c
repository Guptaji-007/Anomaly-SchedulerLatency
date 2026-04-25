/*
 * MEMORY WORKLOAD
 * Purpose: Memory-intensive operations causing page faults
 * Pattern: Periodic spikes from page faults and allocation
 * Label: memory_pressure
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

void* memory_workload_thread(void* arg) {
    size_t size = 50 * 1024 * 1024;  // 50 MB
    
    for (int i = 0; i < 50; i++) {
        // Allocate large memory
        char* buffer = malloc(size);
        if (!buffer) continue;
        
        // Touch every page to cause page faults
        for (size_t j = 0; j < size; j += 4096) {
            buffer[j] = (char)i;
        }
        
        // Random access pattern
        for (int j = 0; j < 1000; j++) {
            int idx = (rand() % (size / sizeof(int))) * sizeof(int);
            ((int*)buffer)[idx / sizeof(int)] += 1;
        }
        
        free(buffer);
        usleep(50000);  // Sleep between iterations
    }
    
    return NULL;
}

int main() {
    int num_threads = 2;
    pthread_t tids[num_threads];
    
    printf("Starting MEMORY workload (%d threads)...\n", num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, memory_workload_thread, NULL);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    printf("MEMORY workload completed\n");
    return 0;
}
