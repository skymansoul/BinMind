/* CWE-190: Narrow type in multiplication before widening
 * count is uint16_t, multiplied by sizeof(item_t)=128 before widening to size_t.
 * count=512 → 512*128=65536 in uint16_t wraps to 0 → malloc(0).
 * EXPECT: TP
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef struct { char data[128]; } item_t;
void load_items(uint16_t count, item_t *src) {
    size_t alloc_sz = count * sizeof(item_t); /* 16-bit multiply, then widen */
    item_t *buf = (item_t*)malloc(alloc_sz);
    if (!buf) return;
    memcpy(buf, src, count * sizeof(item_t));
    free(buf);
}
