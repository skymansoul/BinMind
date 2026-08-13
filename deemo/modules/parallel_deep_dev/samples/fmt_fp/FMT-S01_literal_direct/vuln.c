#include <stdio.h>

static void safe_literal(const char *user)
{
    printf("%s", user);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_literal(argv[1]);
    return 0;
}
