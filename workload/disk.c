// disk_io_workload.c
#include <stdio.h>

int main()
{
    FILE *f;

    while (1)
    {
        f = fopen("temp.txt", "a");

        for (int i = 0; i < 100000; i++)
            fprintf(f, "test\n");

        fclose(f);
    }
}
