#include <stdio.h>
#include <stdlib.h>

static void safe_distinct(void)
{
    char *p = (char *)malloc(16);
    char *q = (char *)malloc(16);
    if (!p || !q)
        return;
    free(p);
    q[0] = 1;
    free(q);
}

int main(void)
{
    safe_distinct();
    return 0;
}
