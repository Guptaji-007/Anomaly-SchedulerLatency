// contended_latency.c
#include <pthread.h>
#include <unistd.h>

void *worker(void *arg) {
    while (1) {
        usleep(20000);  
    }
}

int main() {
    pthread_t t[4];

    for (int i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, NULL);

    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
}
