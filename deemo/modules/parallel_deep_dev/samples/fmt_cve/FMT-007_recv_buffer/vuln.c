#include <stdio.h>
#include <string.h>

static void recv_trigger(const char *payload)
{
    char buf[64];
    memcpy(buf, payload, strlen(payload) + 1);
    printf(buf);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    recv_trigger(argv[1]);
    return 0;
}
