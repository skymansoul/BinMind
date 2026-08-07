/* FP-TEST-02: affine relation proves write <= alloc for all n >= 0.
 * malloc(n*4+8), memcpy(buf, src, n*4).
 * diff = write - alloc = 4n - (4n+8) = -8 < 0 for all n.
 * Stage D (affine_relation) should prove SAFE and FILTER.
 */
#include <stdlib.h>
#include <string.h>

void buffer_copy(int n) {
    if (n <= 0) n = 1;
    /* alloc: 4n+8 bytes */
    char *buf = (char *)malloc(n * 4 + 8);
    if (buf == NULL) return;
    /* write: 4n bytes — always 8 bytes less than alloc */
    memcpy(buf, "fixed_data_placeholder_32bytes", n * 4);
    free(buf);
}

int main(void) {
    buffer_copy(10);
    buffer_copy(100);
    return 0;
}
