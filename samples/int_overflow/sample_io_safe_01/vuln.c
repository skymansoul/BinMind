/* SAFE: Guarded multiplication — overflow check prevents issue
 * if (count > 0x10000000 / sizeof(item_t)) return → safe alloc.
 * EXPECT: TN (FP filter should recognize the guard)
 */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef struct { char data[64]; } item_t;
void safe_alloc_items(int count, item_t *src) {
    if (count <= 0) return;
    if (count > 0x10000000 / (int)sizeof(item_t)) return; /* overflow guard */
    size_t sz = (size_t)count * sizeof(item_t); /* safe: count bounded */
    item_t *buf = (item_t*)malloc(sz);
    if (!buf) return;
    memcpy(buf, src, sz);
    free(buf);
}
