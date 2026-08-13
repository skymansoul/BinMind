#include <stdio.h>
#include <stdlib.h>

static void safe_branch_exclusive(int flag)
{
    char *p = (char *)malloc(16);
    if (!p)
        return;
    if (flag) {
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
    safe_branch_exclusive(atoi(argv[1]));
    return 0;
}
