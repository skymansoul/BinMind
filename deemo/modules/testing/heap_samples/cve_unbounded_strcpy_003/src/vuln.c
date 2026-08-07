/* Unbounded strcpy into heap buffer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;
    if (argc > 1) strcpy(buf, argv[1]);  /* BUG: no length check */
    printf("[*] %s\n", buf);
    free(buf);
    return 0;
}
