#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    unsigned char *buf = (unsigned char *)malloc(256);
    if (!buf) return 1;
    size_t len = argc > 1 ? strlen(argv[1]) : 16;
    size_t ok = len;                 /* 守卫变量经赋值链 */
    if (ok <= 256) {
        memcpy(buf, argv[1], ok);    /* 守卫保证不越界 */
        printf("[*] %zu\n", ok);
    }
    free(buf);
    return 0;
}
