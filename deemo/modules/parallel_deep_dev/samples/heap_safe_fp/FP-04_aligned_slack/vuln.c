#include <stdio.h>
#include <stdlib.h>

static void safe_aligned(void)
{
    char *buf = (char *)malloc(17);
    if (!buf)
        return;
    buf[24] = 1;
    buf[31] = 2;
    free(buf);
}

int main(void)
{
    safe_aligned();
    return 0;
}
