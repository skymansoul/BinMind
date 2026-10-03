#include <stdio.h>
#include <stdlib.h>

static void safe_null_loop(void)
{
    char *p = (char *)malloc(16);
    if (!p)
        return;
    free(p);
    p = 0;
    while (p)
        p[0] = 1;
}

int main(void)
{
    safe_null_loop();
    return 0;
}
