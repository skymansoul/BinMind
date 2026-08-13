#include <stdio.h>
#include <stdlib.h>

static void safe_null_guard(void)
{
    char *p = (char *)malloc(16);
    if (!p)
        return;
    free(p);
    p = 0;
    if (p)
        p[0] = 1;
}

int main(void)
{
    safe_null_guard();
    return 0;
}
