#include <stdio.h>

static void safe_fprintf(FILE *fp, const char *user)
{
    fprintf(fp, "%s\n", user);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    safe_fprintf(stdout, argv[1]);
    return 0;
}
