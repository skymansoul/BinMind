/* CVE-2021-20226 — Linux kernel zerocopy io_uring refcount UAF/double-free
 * But heap aspect: fixed-size buffer pool with wrong size calculation */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    unsigned n_bufs = 256;
    unsigned buf_sz = 4096;
    // BUG: wrong multiplication order — n_bufs * (buf_sz + header) != n_bufs * buf_sz + header
    unsigned alloc = n_bufs * buf_sz;  // missing header overhead
    char *pool = (char *)malloc(alloc);
    if (pool) {
        unsigned actual_use = n_bufs * (buf_sz + 16);  // each buffer has 16-byte header
        memset(pool, 0x41, actual_use);  // HEAP OVERFLOW: 256*16 = 4096 extra bytes
        printf("CVE-2021-20226: alloc=%u write=%u\n", alloc, actual_use);
        free(pool);
    }
    return 0;
}
