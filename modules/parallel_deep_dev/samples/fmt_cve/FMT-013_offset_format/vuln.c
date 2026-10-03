#include <stdio.h>
#include <string.h>

static void off_trigger(const char *input)
{
    char buf[128];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf(buf + 0);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    off_trigger(argv[1]);
    return 0;
}
