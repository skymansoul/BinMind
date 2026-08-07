/* intof-17: realloc 截断 — size_t sz > 2^32 截断为 32-bit
 * movabs rax, sz64; mov DWORD PTR [...], eax; ... call realloc
 */
#include <stdlib.h>
#include <stdint.h>
int main() {
    void *p = malloc(128);
    size_t sz = 0x100000001;
    unsigned n = (unsigned)sz;
    p = realloc(p, n);  // realloc to 1 byte instead of 4GB+1
    free(p);
    return 0;
}
