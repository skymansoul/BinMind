#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;
    char *nb = (char *)realloc(buf, 512);
    if (!nb) { free(buf); return 1; }
    memset(nb, 'R', 512);            /* 新大小 512 内 */
    printf("[*] %c\n", nb[511]);
    free(nb);
    return 0;
}
