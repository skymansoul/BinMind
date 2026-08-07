/* Access beyond aligned chunk boundary */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    char *a = (char *)malloc(32);
    char *b = (char *)malloc(32);
    if (!a || !b) return 1;
    memset(a, 'A', 32); memset(b, 'B', 32);
    size_t o = argc > 1 ? (size_t)atoi(argv[1]) : 40;
    printf("[*] a[%zu]='%c'\n", o, a[o]);  /* BUG: reads beyond a */
    a[o] = 'X';
    printf("[*] b[0]='%c'\n", b[0]);
    free(a); free(b);
    return 0;
}
