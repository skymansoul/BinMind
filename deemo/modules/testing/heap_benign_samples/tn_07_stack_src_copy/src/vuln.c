#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char stack_src[128];
    memset(stack_src, 'S', sizeof(stack_src));
    char *buf = (char *)malloc(128);
    if (!buf) return 1;
    memcpy(buf, stack_src, 128);     /* ¥Û–°∆•≈‰ */
    printf("[*] %c\n", buf[0]);
    free(buf);
    return 0;
}
