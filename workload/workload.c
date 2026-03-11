#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

void *worker(void *arg) {
    for (int i = 0; i < 20; i++) {
        volatile unsigned long long x = 0;

        for (unsigned long long j = 0; j < 50000000ULL; j++)
            x += j;

        usleep(100000);
    }
    return NULL;
}

int main() {
    pthread_t t1, t2;

    printf("Running workload...\n");

    pthread_create(&t1, NULL, worker, NULL);
    pthread_create(&t2, NULL, worker, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    printf("Done.\n");
    return 0;
}
