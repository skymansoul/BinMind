#include <stdio.h>
#include <stdlib.h>

static void safe_local_lit(int n)
{
    char *fmt = "%d";
    printf(fmt, n);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_local_lit(atoi(argv[1]));
    return 0;
}
