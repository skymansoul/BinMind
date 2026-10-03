#include <stdio.h>
#include <stdlib.h>

static void safe_reborn(int v)
{
    char *p = (char *)malloc(16);
    if (!p)
        return;
    free(p);
    p = (char *)malloc(16);
    if (!p)
        return;
    p[0] = (char)v;
    free(p);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_reborn(atoi(argv[1]));
    return 0;
}
