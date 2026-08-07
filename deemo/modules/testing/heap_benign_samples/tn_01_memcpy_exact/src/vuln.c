#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned char *buf = (unsigned char *)malloc(256);
    if (!buf) return 1;
    unsigned char src[256];
    memset(src, 1, sizeof(src));
    memcpy(buf, src, 256);   /* 大小精确等于分配 */
    printf("[*] %d\n", buf[0]);
    free(buf);
    return 0;
}
