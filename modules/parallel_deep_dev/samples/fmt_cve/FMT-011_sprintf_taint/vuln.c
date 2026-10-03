#include <stdio.h>
#include <stdlib.h>

static void sp_trigger(const char *fmt, int n)
{
    char buf[128];
    sprintf(buf, fmt, n);
}

int main(int argc, char **argv)
{
    if (argc < 3)
        return 1;
    sp_trigger(argv[1], atoi(argv[2]));
    return 0;
}
