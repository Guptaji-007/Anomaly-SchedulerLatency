/*
 * PIPE/IPC WORKLOAD
 * Purpose: Inter-process communication causing context switches
 * Pattern: Periodic spikes from IPC waits
 * Label: ipc_communication
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

void* pipe_reader_thread(void* arg) {
    int fd = (int)(intptr_t)arg;
    char buffer[1024];
    
    for (int i = 0; i < 500; i++) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n > 0) {
            // Small processing
            volatile int sum = 0;
            for (int j = 0; j < n; j++) {
                sum += buffer[j];
            }
        }
    }
    
    return NULL;
}

void* pipe_writer_thread(void* arg) {
    int fd = (int)(intptr_t)arg;
    char buffer[1024];
    
    memset(buffer, 'A', sizeof(buffer));
    
    for (int i = 0; i < 500; i++) {
        write(fd, buffer, sizeof(buffer));
        usleep(1000);  // Small delay between writes
    }
    
    return NULL;
}

int main() {
    int pipe_fds[2];
    
    printf("Starting IPC/PIPE workload...\n");
    
    // Create multiple pipes for communication
    for (int p = 0; p < 2; p++) {
        if (pipe(pipe_fds) < 0) {
            perror("pipe");
            return 1;
        }
        
        pthread_t reader, writer;
        pthread_create(&reader, NULL, pipe_reader_thread, (void*)(intptr_t)pipe_fds[0]);
        pthread_create(&writer, NULL, pipe_writer_thread, (void*)(intptr_t)pipe_fds[1]);
        
        pthread_join(reader, NULL);
        pthread_join(writer, NULL);
        
        close(pipe_fds[0]);
        close(pipe_fds[1]);
    }
    
    printf("IPC/PIPE workload completed\n");
    return 0;
}
