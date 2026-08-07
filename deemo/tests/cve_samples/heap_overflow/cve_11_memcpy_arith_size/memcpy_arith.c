/*
 * CVE-11: memcpy 算术大小堆溢出
 *
 * 模式: malloc(N), memcpy(buf, src, N+K) where K > 0
 * 触发: N=64, K=16 → memcpy 写入 80B → 溢出 16B
 *
 * 对应真实 CVE: CVE-2023-27535 (libcurl FTP 堆溢出)
 * 检测预期: write_size=80 > alloc=64, alignment 不帮助 (80 > 对齐后 80)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int n = 64;
    char *buf = (char *)malloc(n);
    if (!buf) return 1;

    char src[80];
    memset(src, 'C', 80);

    // memcpy 大小 = n + 16 = 80 > malloc(64) → 溢出
    memcpy(buf, src, n + 16);

    printf("memcpy arith overflow done\n");
    free(buf);
    return 0;
}
