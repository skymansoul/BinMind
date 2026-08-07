/*
 * CVE-30: 跨函数仅分配 — alloc在funcA, 无写入, 调用者写入
 *
 * 模式: make_buf(64)返回指针, caller在offset 72写入 → 溢出
 * 触发: 跨函数约束传播需关联alloc约束到caller上下文
 *
 * 对应: 类似 CVE-2017-17052 (mm 堆溢出, 工厂函数分配)
 * 检测预期: PROVEN_OVERFLOW
 */
#include <stdio.h>
#include <stdlib.h>

char *make_buf(int sz) {
    return (char *)malloc(sz);
}

int main(void) {
    char *buf = make_buf(64);
    if (!buf) return 1;

    /* offset 72 + 8 = 80 > usable(64)=72 → overflow */
    *(long *)(buf + 72) = 0x4646464646464646L;

    printf("cross_func_alloc_only done\n");
    free(buf);
    return 0;
}
