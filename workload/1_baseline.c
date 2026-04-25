/*
 * BASELINE WORKLOAD
 * Purpose: Minimal system activity - normal operation baseline
 * Pattern: Low latency, low variance, predictable
 * Label: baseline
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

void busy_wait(int iterations) {
    volatile int sum = 0;
    for (int i = 0; i < iterations; i++) {
        sum += i * i;
    }
}

void* baseline_thread(void* arg) {
    for (int i = 0; i < 1000; i++) {
        // Light CPU work
        busy_wait(100);
        // Sleep to avoid 100% CPU
        usleep(100);
    }
    return NULL;
}

int main() {
    pthread_t tid;
    printf("Starting BASELINE workload (minimal activity)...\n");
    
    pthread_create(&tid, NULL, baseline_thread, NULL);
    pthread_join(tid, NULL);
    
    printf("BASELINE workload completed\n");
    return 0;
}
