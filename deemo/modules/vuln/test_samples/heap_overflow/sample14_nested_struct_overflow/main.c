/* 嵌套结构深层偏移堆溢出.
 *
 * Outer: { header[64], Inner inner }, Inner: { meta[32], data[256] }
 * sizeof(Outer) = 352, 但 outer->inner.data[256] 偏移可能=352 → 溢出.
 * Expected: TP (struct-aware offset tracking)
 */
#include <stdlib.h>
#include <string.h>

typedef struct {
    char meta[32];
    char data[256];
} Inner;

typedef struct {
    char header[64];
    Inner inner;
} Outer;

int main() {
    Outer *obj = (Outer *)malloc(sizeof(Outer));  /* 64+32+256=352 */
    if (!obj) return 1;
    /* sizeof(Outer)=352, data[0] offset=96, data[256] offset=352 → 溢出 */
    memset(obj->inner.data + 256, 0, 16);  /* OVERFLOW by 16 */
    free(obj);
    return 0;
}
