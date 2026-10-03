#include <stdio.h>

static void safe_snp_fputs(const char *user)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", user);
    fputs(buf, stdout);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_snp_fputs(argv[1]);
    return 0;
}
