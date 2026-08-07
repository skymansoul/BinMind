#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = (char *)malloc(64);
    if (!p) return 1;
    strcpy(p, "safe_null");
    free(p);
    p = NULL;  /* safe: null after free */
    if (p) {
        p[0] = 'X';  /* unreachable */
    }
    printf("null after free: safe\n");
    return 0;
}
