#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    strcpy(buf, "literal short");    /* 长度 14 <= 64 */
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
