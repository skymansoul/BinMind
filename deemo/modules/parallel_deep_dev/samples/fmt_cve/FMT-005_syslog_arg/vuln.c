#include <stdio.h>

static void syslog_trigger(const char *detail)
{
    printf("[err] ");
    printf(detail);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    syslog_trigger(argv[1]);
    return 0;
}
