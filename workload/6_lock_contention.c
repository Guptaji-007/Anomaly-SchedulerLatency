/*
 * LOCK CONTENTION WORKLOAD
 * Purpose: Mutex/lock contention causing wait times
 * Pattern: Spikes when threads wait for locks
 * Label: lock_contention
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
volatile int shared_counter = 0;

void* lock_contention_thread(void* arg) {
    for (int i = 0; i < 1000; i++) {
        // Lock for critical section
        pthread_mutex_lock(&lock);
        
        // Do some work inside critical section
        for (int j = 0; j < 10000; j++) {
            shared_counter += j % 10;
        }
        
        pthread_mutex_unlock(&lock);
        
        // Short sleep
        usleep(100);
    }
    return NULL;
}

int main() {
    int num_threads = 8;  // More threads = more contention
    pthread_t tids[num_threads];
    
    printf("Starting LOCK CONTENTION workload (%d threads)...\n", num_threads);
    
    for (int i = 0; i < num_threads; i++) {
        pthread_create(&tids[i], NULL, lock_contention_thread, NULL);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    printf("LOCK CONTENTION workload completed (counter=%d)\n", shared_counter);
    return 0;
}
