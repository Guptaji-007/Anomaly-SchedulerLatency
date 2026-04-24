/*
 * MIXED WORKLOAD
 * Purpose: Combination of CPU + I/O + memory + locking
 * Pattern: Variable spikes from all causes
 * Label: mixed
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void* mixed_workload_thread(void* arg) {
    char buffer[4096];
    char filename[100];
    int tid = (int)(intptr_t)arg;
    
    snprintf(filename, sizeof(filename), "/tmp/mixed_%d.tmp", tid);
    
    for (int iter = 0; iter < 100; iter++) {
        // CPU work
        volatile int cpu_work = 0;
        for (int i = 0; i < 5000; i++) {
            cpu_work += i * i;
        }
        
        // Memory allocation
        char* mem = malloc(1024 * 1024);
        if (mem) {
            memset(mem, 0xAA, 1024 * 1024);
            free(mem);
        }
        
        // I/O work
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd >= 0) {
            write(fd, buffer, sizeof(buffer));
            fsync(fd);
            close(fd);
        }
        
        // Yield
        sched_yield();
        
        usleep(10000);
    }
    
    unlink(filename);
    return NULL;
}

int main() {
    int num_threads = 4;
    pthread_t tids[num_threads];
    
    printf("Starting MIXED workload (%d threads)...\n", num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, mixed_workload_thread, (void*)(intptr_t)i);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    printf("MIXED workload completed\n");
    return 0;
}
