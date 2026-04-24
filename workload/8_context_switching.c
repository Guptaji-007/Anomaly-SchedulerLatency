/*
 * CONTEXT SWITCH WORKLOAD
 * Purpose: Force frequent context switches
 * Pattern: Many voluntary yields causing scheduler activity
 * Label: context_switching
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sched.h>

void* context_switch_thread(void* arg) {
    for (int i = 0; i < 2000; i++) {
        // Voluntary yield - forces context switch
        sched_yield();
        
        // Tiny bit of work
        volatile int x = 0;
        for (int j = 0; j < 100; j++) {
            x += j;
        }
    }
    return NULL;
}

int main() {
    int num_threads = 16;  // Many threads to cause switching
    pthread_t tids[num_threads];
    
    printf("Starting CONTEXT SWITCHING workload (%d threads)...\n", num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, context_switch_thread, NULL);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    printf("CONTEXT SWITCHING workload completed\n");
    return 0;
}
