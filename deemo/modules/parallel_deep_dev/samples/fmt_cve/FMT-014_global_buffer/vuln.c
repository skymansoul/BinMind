#include <stdio.h>
#include <string.h>

static char g_buf[128];

static void global_trigger(const char *input)
{
    strcpy(g_buf, input);
    printf(g_buf);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    global_trigger(argv[1]);
    return 0;
}
