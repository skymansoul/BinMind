/* CWE-122: posix_memalign allocation then write beyond aligned boundary */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    void *p; posix_memalign(&p, 64, 64);
    memset(p, 0x41, 128); /* write 128 into 64-byte aligned alloc */
    free(p); return 0;
}
