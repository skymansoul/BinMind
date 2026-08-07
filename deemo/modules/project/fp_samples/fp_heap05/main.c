#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(0x40);
    if (!buf) return 1;
    for (int i = 0; i < 0x100; i++) buf[i] = (char)i;
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
