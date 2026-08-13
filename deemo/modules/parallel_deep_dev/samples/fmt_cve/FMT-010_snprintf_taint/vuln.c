#include <stdio.h>
#include <stdlib.h>

static void snp_trigger(const char *fmt, int n)
{
    char buf[128];
    snprintf(buf, sizeof(buf), fmt, n);
}

int main(int argc, char **argv)
{
    if (argc < 3)
        return 1;
    snp_trigger(argv[1], atoi(argv[2]));
    return 0;
}
