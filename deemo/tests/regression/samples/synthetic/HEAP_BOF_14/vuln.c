/* HEAP_BOF_14: memalign overflow — aligned alloc with write beyond */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int c, char **v) {
    void *p; posix_memalign(&p, 32, 32);
    memset(p, 0x41, 256); free(p); return 0;
}
