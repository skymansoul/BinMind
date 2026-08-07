#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    strcpy(buf, "hello");
    free(buf);
    /* UAF: write to freed buffer */
    buf[0] = 'H';
    printf("uaf: %s\n", buf);
    return 0;
}
