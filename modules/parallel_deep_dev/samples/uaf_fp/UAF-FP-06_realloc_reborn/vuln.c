#include <stdio.h>
#include <stdlib.h>

static void safe_realloc_reborn(int n)
{
    char *p = (char *)malloc(16);
    if (!p)
        return;
    free(p);
    p = (char *)realloc(0, (size_t)n);
    if (!p)
        return;
    p[0] = 1;
    free(p);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_realloc_reborn(atoi(argv[1]));
    return 0;
}
