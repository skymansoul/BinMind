#include <stdio.h>

static void log_trigger(const char *msg)
{
    fprintf(stderr, msg);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    log_trigger(argv[1]);
    return 0;
}
