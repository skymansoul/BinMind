#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void safe_copy(const char *input, size_t n)
{
    char *buf = (char *)malloc(n);
    if (!buf)
        return;
    memcpy(buf, input, n);
    free(buf);
}

int main(int argc, char **argv)
{
    if (argc < 3)
        return 1;
    size_t n = (size_t)strtoul(argv[1], NULL, 10);
    safe_copy(argv[2], n);
    return 0;
}
