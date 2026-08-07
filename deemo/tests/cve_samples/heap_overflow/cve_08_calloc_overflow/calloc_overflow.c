/*
 * CVE-08: calloc 堆溢出
 *
 * 模式: calloc(nmemb=16, size=4) → 分配 64B, memset 写入 128B → 溢出
 * 触发: 后续写入超过 calloc 乘积的大小
 *
 * 对应真实 CVE: CVE-2020-8287 (Node.js HTTP parser)
 * 检测预期: calloc 乘积正确解析 (16*4=64), 128 > 64 → 检出
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    // calloc(16, 4) = 64B — nmemb*size 的乘积
    int *buf = (int *)calloc(16, sizeof(int));
    if (!buf) return 1;

    // 写入 32 个 int = 128B > 64B 分配 → 溢出
    for (int i = 0; i < 32; i++) {
        buf[i] = i;
    }

    printf("calloc overflow done\n");
    free(buf);
    return 0;
}
