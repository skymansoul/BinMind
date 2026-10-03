/*
 * 整数溢出 → 堆溢出 — count * elem_size 溢出后小分配, 大写入
 * alloc: count(65536) * elem_size(4) = 0 mod 2**32 = 0 → malloc(0+1) ≈ 16
 * write: count * elem_size = 256K → 巨大溢出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void process_items(uint32_t count, uint32_t elem_size) {
    /* 漏洞: count * elem_size 在 32 位下乘积回绕 → 小分配 */
    size_t total = (size_t)(count * elem_size);
    if (total == 0) total = 1;  /* 防止 malloc(0) */

    char *buf = (char *)malloc(total);
    if (!buf) return;

    /* write 使用 64 位乘积的实际大小 (可能远超 total) */
    size_t actual = (size_t)count * (size_t)elem_size;
    memset(buf, 'X', actual);
    printf("alloc=%zu actual=%zu\n", total, actual);
    free(buf);
}

int main(void) {
    /* count=65536, elem=65536 → 32位乘积回绕为 0, 64位乘积 = 2^32 */
    process_items(65536, 65536);
    return 0;
}
