#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void safe_strcpy(void)
{
    char *buf = (char *)malloc(64);
    if (!buf)
        return;
    strcpy(buf, "hello world");
    free(buf);
}

int main(void)
{
    safe_strcpy();
    return 0;
}
