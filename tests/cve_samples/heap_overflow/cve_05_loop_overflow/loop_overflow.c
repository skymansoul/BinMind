/*
 * CVE-05: 循环边界堆溢出
 *
 * 模式: 循环上界 N > 分配大小 M, 每次迭代写入 1B
 * 触发: malloc(32), for(i=0;i<64;i++) buf[i]=x → 溢出 32B
 *
 * 对应真实 CVE: CVE-2018-16864 (systemd-journald 堆溢出)
 * 检测预期: 循环上界推断 cmp i,64 → bound=64 > alloc=32 → 检出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(32);
    if (!buf) return 1;

    // 循环上界 64 > 分配 32 → 溢出
    for (int i = 0; i < 64; i++) {
        buf[i] = 'A';
    }

    printf("loop overflow done\n");
    free(buf);
    return 0;
}
