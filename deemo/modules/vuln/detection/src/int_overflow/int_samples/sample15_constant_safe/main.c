#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 256

int main(void) {
    /* SAFE: constant size, no overflow possible */
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) return 1;
    strncpy(buf, "constant allocation", BUF_SIZE - 1);
    buf[BUF_SIZE - 1] = '\0';
    printf("safe constant: %s\n", buf);
    free(buf);
    return 0;
}
