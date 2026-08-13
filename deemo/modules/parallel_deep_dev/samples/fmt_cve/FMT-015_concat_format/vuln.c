#include <stdio.h>
#include <string.h>

static void concat_trigger(const char *input)
{
    char buf[128];
    strcpy(buf, "log: ");
    strcat(buf, input);
    printf(buf);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    concat_trigger(argv[1]);
    return 0;
}
