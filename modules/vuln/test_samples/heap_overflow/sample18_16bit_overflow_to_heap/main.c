/* 16-bit 整数溢出 → 堆溢出.
 *
 * uint16_t size = 65536 wraps to 0, malloc(0) returns min chunk,
 * but write expects 65536 bytes → OVERFLOW.
 * Expected: TP (16-bit overflow → heap)
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main() {
    uint16_t count = 0;  /* will overflow when set to 65536 */
    /* simulate: count = 65536 wrapping to 0 */
    count = 0;  /* wraps from 65536 */
    size_t alloc_size = count * 16;  /* 0 * 16 = 0 */
    char *buf = (char *)malloc(alloc_size ? alloc_size : 1);
    if (!buf) return 1;
    /* actual write target: count*16 bytes, but count wrapped → OVERFLOW */
    memset(buf, 'X', 65536U * 16);
    free(buf);
    return 0;
}
