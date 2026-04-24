/*
 * DISK I/O WORKLOAD
 * Purpose: Heavy disk operations causing context switches
 * Pattern: High variance, large periodic spikes
 * Label: disk_io
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

void* disk_io_thread(void* arg) {
    char buffer[4096];
    char filename[100];
    int tid = (int)(intptr_t)arg;
    
    snprintf(filename, sizeof(filename), "/tmp/workload_test_%d.tmp", tid);
    
    for (int i = 0; i < 100; i++) {
        // Write to disk
        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (fd >= 0) {
            for (int j = 0; j < 10; j++) {
                write(fd, buffer, sizeof(buffer));
            }
            fsync(fd);  // Force write to disk
            close(fd);
        }
        
        // Read from disk
        fd = open(filename, O_RDONLY);
        if (fd >= 0) {
            for (int j = 0; j < 10; j++) {
                read(fd, buffer, sizeof(buffer));
            }
            close(fd);
        }
        
        // Clean up
        unlink(filename);
        usleep(10000);  // Small sleep between iterations
    }
    
    return NULL;
}

int main() {
    int num_threads = 4;
    pthread_t tids[num_threads];
    
    printf("Starting DISK I/O workload (%d threads)...\n", num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, disk_io_thread, (void*)(intptr_t)i);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    printf("DISK I/O workload completed\n");
    return 0;
}
