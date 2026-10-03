/* intof-19: malloc(UINT32_MAX) — 32-bit 最大值作为分配大小
 * mov ecx, 0xFFFFFFFF; call malloc
 */
#include <stdlib.h>
#include <stdint.h>
int main() {
    char *p = malloc(UINT32_MAX);  // 4GB allocation
    free(p);
    return 0;
}
