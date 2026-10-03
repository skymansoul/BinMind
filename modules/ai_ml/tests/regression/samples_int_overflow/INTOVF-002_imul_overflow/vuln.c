/* INTOVF-002: imul溢出——乘法溢出导致分配不足
 * 场景: calloc(nmemb, size) → nmemb*size可能溢出
 *   若nmemb=65536, size=65536 → product=4G → 截断为0 → calloc(0)
 * 检测器能力: imul溢出→结果传递给calloc→CONFIRMED/LIKELY
 * 与CVE-2020-10713的grub2漏洞模式相同
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
    int id;
    double value;
} DataPoint;

DataPoint *load_datapoints(size_t count, size_t elem_size) {
    /* BUG: count * elem_size可能溢出size_t
     * 若count=0x100000, elem_size=0x10000 → 溢出 */
    size_t alloc_size = count * elem_size;

    DataPoint *pts = (DataPoint *)malloc(alloc_size);
    if (!pts) return NULL;

    /* 初始化——若溢出使alloc_size变小, 这里会越界写 */
    for (size_t i = 0; i < count; i++) {
        pts[i].id = (int)i;
        pts[i].value = 0.0;
    }
    return pts;
}

/* 安全的对照: 使用__builtin_mul_overflow检测 */
DataPoint *load_datapoints_safe(size_t count, size_t elem_size) {
    size_t alloc_size;
    if (__builtin_mul_overflow(count, elem_size, &alloc_size)) {
        return NULL;  /* 溢出——拒绝分配 */
    }
    return (DataPoint *)malloc(alloc_size);
}

int main(void) {
    DataPoint *pts = load_datapoints(100, sizeof(DataPoint));
    if (pts) {
        printf("loaded %d points\n", pts[0].id);
        free(pts);
    }
    return 0;
}
