#include <stdio.h>

static const char *FMT = "user=%s";

static void safe_const_var(const char *user)
{
    printf(FMT, user);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_const_var(argv[1]);
    return 0;
}
