#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int n = -1;
    /* n cast to size_t → SIZE_MAX (huge allocation) */
    size_t sz = (size_t)n;
    char *buf = (char *)malloc(sz);
    if (!buf) {
        printf("malloc(%zu) failed (expected)\n", sz);
        return 0;
    }
    printf("unexpected: malloc(-1) succeeded\n");
    free(buf);
    return 0;
}
