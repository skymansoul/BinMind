/* CVE-2021-20226 — Linux kernel io_uring integer overflow
   Type: integer_overflow   gcc -O0 io_uring_int_overflow.c -o io_uring_int_overflow
   io_uring IORING_OP_PROVIDE_BUFFERS had integer overflow in size calc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void provide_buffers(int num_bufs, int buf_size) {
    /* BUG: num_bufs * buf_size can overflow 32-bit int */
    int total = num_bufs * buf_size;
    char *pool = (char *)malloc(total);
    if (!pool) return;
    memset(pool, 0, (unsigned int)(num_bufs * buf_size));
    printf("Pool: %d bytes\n", total);
    free(pool);
}
int main() {
    provide_buffers(65536, 65536);  /* 65536*65536 = 0 (32-bit overflow) */
    return 0;
}
