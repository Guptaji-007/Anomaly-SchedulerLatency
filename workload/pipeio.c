// pipe_io_workload.c
#include <unistd.h>
#include <stdio.h>

int main()
{
    int fd[2];
    pipe(fd);

    if (fork() == 0)
    {
        while (1)
        {
            char buf[10];
            read(fd[0], buf, sizeof(buf));
        }
    }
    else
    {
        while (1)
        {
            write(fd[1], "hello", 5);
        }
    }
}
