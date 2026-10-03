/* UAF-TP-01: free(p) 后直接 p[0] 写入. */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *p = (char *)malloc(16);
    if (!p) return 1;
    memcpy(p, "hello", 6);
    free(p);
    p[0] = 'X';
    printf("%c\n", p[0]);
    return 0;
}
