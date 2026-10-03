#include <stdio.h>
#include <stdlib.h>

int main(void) {
    char *src = (char *)malloc(64);
    if (!src) return 1;
    sprintf(src, "value is %d", 42);
    /* copy value before free */
    int saved = src[0];
    free(src);
    /* safe: uses saved copy, not freed ptr */
    printf("saved value: %c\n", (char)saved);
    return 0;
}
