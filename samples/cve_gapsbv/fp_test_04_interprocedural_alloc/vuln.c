/* FP-TEST-04: cross-function alloc→write chain with shared size variable.
 * alloc_buf(n) calls malloc(n*4+8), caller calls fill_buf(buf, n*4).
 * The alloc size (4n+8) and write size (4n) share symbol n.
 * InterproceduralAffineTracker should compute diff = -8 → SAFE.
 */
#include <stdlib.h>
#include <string.h>

/* helper: allocate buffer of size n*4+8 */
static char *alloc_buf(int n) {
    return (char *)malloc(n * 4 + 8);
}

/* helper: fill buffer with n bytes */
static void fill_buf(char *buf, int n) {
    if (buf && n > 0) {
        memcpy(buf, "placeholder_data_for_testing_32b", n);
    }
}

void process(int n) {
    if (n <= 0) n = 1;
    int write_sz = n * 4;  /* 4n */
    char *buf = alloc_buf(n);  /* alloc: 4n+8 */
    if (buf) {
        fill_buf(buf, write_sz);  /* write: 4n, diff = -8 */
        free(buf);
    }
}

int main(void) {
    process(25);
    return 0;
}
