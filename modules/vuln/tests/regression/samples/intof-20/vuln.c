/* intof-20: calloc 截断 — calloc(n, 1) where n 来自截断的 64-bit 值
 * movabs rax, >2^32; mov [...], eax; mov ecx, eax; mov edx, 1; call calloc
 */
#include <stdlib.h>
#include <stdint.h>
int main() {
    size_t big = 0x100000005;
    unsigned small = (unsigned)big;  // truncation: 0x100000005 → 5
    void *p = calloc(small, 1);      // 只分配 5 字节, 而非 4GB+5
    free(p);
    return 0;
}
