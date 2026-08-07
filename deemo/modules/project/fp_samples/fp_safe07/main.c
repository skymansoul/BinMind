#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(40);
    if (!buf) return 1;
    memset(buf, 'f', 48);
    printf("%c\n", buf[0]);
    free(buf);
    return 0;
}
