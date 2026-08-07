/* INTOVF-003: shl位移溢出——左移超界导致宽度溢出
 * 场景: alloc_size = 1 << width; 若width>=31 → 符号溢出或截断
 * 检测器能力: shl by >=31 → 必然溢出或UB
 * 预期: IntOverflowDeepAnalyzer检测shl溢出
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* BUG: shl宽度未检查——width>=31时溢出 */
void *alloc_by_width(int width) {
    /* 1 << 31 = 0x80000000 (有符号int→负值) */
    /* 1 << 32 = 0 (32位下UB) */
    size_t size = (size_t)1 << width;
    return malloc(size);
}

/* BUG: 变体——shl用于数组大小计算 */
int *create_bit_table(int bits) {
    /* 1 << bits溢出: bits=31→2G→有符号溢出, bits>=32→UB */
    int count = 1 << bits;
    int *table = (int *)malloc(count * sizeof(int));
    if (!table) return NULL;
    for (int i = 0; i < count; i++)
        table[i] = 0;
    return table;
}

int main(void) {
    void *p1 = alloc_by_width(10);  /* 1<<10=1024——安全 */
    if (p1) free(p1);

    /* 边界用例: width=20也是安全的(1<<20=1MB) */
    void *p2 = alloc_by_width(20);
    if (p2) free(p2);

    printf("shl overflow test complete\n");
    return 0;
}
