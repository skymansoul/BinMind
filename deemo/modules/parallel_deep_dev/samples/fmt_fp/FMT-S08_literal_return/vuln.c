#include <stdio.h>
#include <stdlib.h>

static const char *get_fmt(void)
{
    return "value=%d";
}

static void safe_ret_fmt(int n)
{
    printf(get_fmt(), n);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_ret_fmt(atoi(argv[1]));
    return 0;
}
