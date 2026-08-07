#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void safe_guarded(const char *input, size_t len, size_t size)
{
    char *buf = (char *)malloc(size);
    if (!buf)
        return;
    if (len > size)
        return;
    memcpy(buf, input, len);
    free(buf);
}

int main(int argc, char **argv)
{
    if (argc < 4)
        return 1;
    size_t len = (size_t)strtoul(argv[1], NULL, 10);
    size_t size = (size_t)strtoul(argv[2], NULL, 10);
    safe_guarded(argv[3], len, size);
    return 0;
}
