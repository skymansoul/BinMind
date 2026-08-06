/* CVE-2023-0461 — Linux kernel UAF in io_uring
   Type: use_after_free (heap)
   gcc -O0 kernel_uaf.c -o kernel_uaf

   Simplified: io_uring had a UAF where a request's buffer was freed
   via IORING_OP_SPLICE but the request object still held a dangling
   reference. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { unsigned char *buf; int len; int refs; } io_request;

io_request *io_alloc(int sz) {
    io_request *r = (io_request *)malloc(sizeof(io_request));
    r->buf = (unsigned char *)malloc(sz); r->len = sz; r->refs = 1;
    return r;
}

void io_free(io_request *r) {
    if (--r->refs <= 0) { free(r->buf); free(r); }
}

int io_splice(io_request *r, int fd) {
    /* BUG: frees r->buf but caller still uses r later */
    if (fd < 0) { free(r->buf); r->buf = NULL; return -1; }
    /* r->buf may be freed already if fd < 0 */
    memset(r->buf, 0, r->len);  /* UAF on heap buffer */
    return 0;
}

int main() {
    io_request *r = io_alloc(512);
    io_splice(r, -1);
    free(r);
    return 0;
}
