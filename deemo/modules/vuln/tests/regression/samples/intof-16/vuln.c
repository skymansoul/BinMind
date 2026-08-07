/* intof-16: 64-bit 大立即数 → malloc — 值 > 2^32
 * movabs rax, 0x100000001; mov rcx, rax; call malloc
 */
#include <stdlib.h>
#include <stdint.h>
int main() {
    volatile size_t big = 0x100000001;
    void *p = malloc(big);  // 4GB+1 allocation
    free(p);
    return 0;
}
