#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    strncpy(buf, argc > 1 ? argv[1] : "hello", 255);  /* œ‘ Ω…œΩÁ */
    buf[255] = '\0';
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
