#include <stdio.h>
#include <stdlib.h>

static void safe_realloc(void)
{
    int *buf = (int *)malloc(16);
    if (!buf)
        return;
    buf = (int *)realloc(buf, 16 * 4);
    if (!buf)
        return;
    int i;
    for (i = 0; i < 16; i++) {
        buf[i] = i;
    }
    free(buf);
}

int main(void)
{
    safe_realloc();
    return 0;
}
