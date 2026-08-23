/* two allocations, one freed, write to wrong buffer */
#include <stdlib.h>
#include <string.h>

void edge_double_alloc(char *src) {
    char *a = (char *)malloc(64);
    char *b = (char *)malloc(128);
    free(a);
    memcpy(b, src, 256);  /* 256 > 128 �� OVERFLOW */
    free(b);
}

int main(void) {
    static char src[300];
    edge_double_alloc(src);  /* memcpy 256 > 128 */
    return 0;
}
