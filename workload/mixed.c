// mixed_system_stress.c
// cpu + sleep + yield
#include <unistd.h>
#include <sched.h>

int main()
{
    while (1)
    {
        for (volatile int i = 0; i < 100000000; i++);
        sched_yield();
        usleep(5000);
    }
}
