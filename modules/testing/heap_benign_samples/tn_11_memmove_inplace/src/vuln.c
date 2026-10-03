#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memset(buf, 'X', 128);
    memmove(buf + 8, buf, 64);       /* 均在 128 内 */
    printf("[*] %c\n", buf[8]);
    free(buf);
    return 0;
}
