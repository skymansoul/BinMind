#include <stdio.h>

static void safe_syslog(const char *user)
{
    printf("login: %s\n", user);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_syslog(argv[1]);
    return 0;
}
