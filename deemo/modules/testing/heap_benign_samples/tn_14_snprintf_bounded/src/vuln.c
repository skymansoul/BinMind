#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;
    int n = snprintf(buf, 256, "value=%d", argc);  /* ио╫Г 256 */
    printf("[*] %d\n", n);
    free(buf);
    return 0;
}
