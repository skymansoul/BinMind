#include <stdio.h>
#include <stdlib.h>

static void safe_loop(size_t n)
{
    int *buf = (int *)malloc(n * 4);
    if (!buf)
        return;
    size_t i;
    for (i = 0; i < n; i++) {
        buf[i] = (int)i;
    }
    free(buf);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    size_t n = (size_t)strtoul(argv[1], NULL, 10);
    safe_loop(n);
    return 0;
}
