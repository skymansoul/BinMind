#include <stdio.h>
#include <string.h>

static void loop_trigger(const char *input)
{
    char buf[64];
    size_t i, n = strlen(input);
    for (i = 0; i < n && i < sizeof(buf) - 1; i++)
        buf[i] = input[i];
    buf[i] = '\0';
    printf(buf);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    loop_trigger(argv[1]);
    return 0;
}
