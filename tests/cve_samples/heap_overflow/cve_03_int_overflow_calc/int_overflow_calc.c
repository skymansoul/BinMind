/*
 * CVE-03: 整数溢出导致堆缓冲区过小
 *
 * 模式: size = count * element_size; 若 count 可控且乘积溢出, 分配不足
 * 触发: count=0x40000001, sizeof(int)=4 → 乘积=0x100000004 → 截断为4 → malloc(4)
 *       然后按 count 个元素写入 → 溢出
 *
 * 对应真实 CVE: CVE-2015-0235 (Ghost — glibc __nss_hostname_digits_dots)
 * 检测预期: 静态分析应标记 size 计算中的潜在整数溢出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_data(unsigned int count) {
    // 整数溢出: count * sizeof(int) 可能回绕
    size_t alloc_size = count * sizeof(int);
    int *buf = (int *)malloc(alloc_size);
    if (!buf) return;

    // 按原始 count 写入 — 若乘积溢出, 此处溢出
    for (unsigned int i = 0; i < count; i++) {
        buf[i] = (int)i;
    }

    printf("processed %u items\n", count);
    free(buf);
}

int main(void) {
    // 触发: count 足够大导致乘积溢出
    process_data(0x40000001);
    return 0;
}
