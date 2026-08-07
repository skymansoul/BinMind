/* CWE-190: Chained overflow — two multiplications
 * width * height * 4 → overflow in intermediate computation.
 * width=0x4000, height=0x4000 → product wraps → small alloc + Bmp frame overflow.
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
void create_bmp(int width, int height, uint8_t *pixels) {
    int row_size = width * 4;                   /* may overflow */
    int total = row_size * height;              /* multiplies overflowed value */
    uint8_t *buf = (uint8_t*)malloc(total);
    if (!buf) return;
    for (int y = 0; y < height; y++)
        memcpy(buf + y * row_size, pixels + y * width * 4, width * 4);
    free(buf);
}
