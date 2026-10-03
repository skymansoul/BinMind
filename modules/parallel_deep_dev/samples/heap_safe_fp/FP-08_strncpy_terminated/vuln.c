#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void safe_strncpy(const char *src, size_t n)
{
    if (n > 64)
        return;
    char *buf = (char *)malloc(64);
    if (!buf)
        return;
    strncpy(buf, src, n - 1);
    buf[n - 1] = '\0';
    free(buf);
}

int main(int argc, char **argv)
{
    if (argc < 3)
        return 1;
    size_t n = (size_t)strtoul(argv[1], NULL, 10);
    safe_strncpy(argv[2], n);
    return 0;
}
