#include <stdio.h>
#include <stdlib.h>

static void safe_exclusive(int ref)
{
    char *p = (char *)malloc(16);
    if (!p)
        return;
    if (ref == 0) {
        free(p);
    } else {
        p[0] = 1;
        free(p);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_exclusive(atoi(argv[1]));
    return 0;
}
