#include <stdio.h>

static void scanf_trigger(const char *line)
{
    char buf[80];
    sscanf(line, "%s", buf);
    printf(buf);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    scanf_trigger(argv[1]);
    return 0;
}
