#include <stdio.h>
#include <stdlib.h>

static void env_trigger(int n)
{
    char *fmt = getenv("LOG_FORMAT");
    if (fmt)
        printf(fmt, n);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    env_trigger(atoi(argv[1]));
    return 0;
}
