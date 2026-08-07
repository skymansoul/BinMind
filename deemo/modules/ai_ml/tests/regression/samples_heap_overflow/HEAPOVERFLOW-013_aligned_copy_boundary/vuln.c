/* HEAPOVERFLOW-013: 对齐拷贝边界测试——跨步区间消除对齐边界误报
 * 场景: malloc(32)在glibc x86_64下实际可用48字节
 *       若拷贝大小以16字节步长变化，最大值48恰好对齐→安全
 *       但简单区间[32,48]会标记为溢出(48 > 48-8=40 margin)
 * 跨步区间[32,48]₁₆ = {32, 48}，最大值48=usable→判定安全
 * 对照: 若max=64则{32,48,64}中64>48→溢出
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* 安全: copy_size∈{32,48}，最大值48=usable，无溢出 */
void aligned_copy_safe(int variant) {
    char *buf = (char *)malloc(32);
    if (!buf) return;

    int copy_size;
    /* 对齐计算: copy_size始终是16的倍数 */
    if (variant < 16) {
        copy_size = 32;
    } else {
        copy_size = 48;
    }
    /* 简单区间看到[32,48]→担心hi=48>usable-margin
     * 跨步区间看到[32,48]₁₆={32,48}→max=48=usable→安全 */
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
           copy_size <= 48 ? copy_size : 48);
    free(buf);
}

/* 危险: copy_size∈{32,48,64}，64>48→溢出 */
void aligned_copy_overflow(int variant) {
    char *buf = (char *)malloc(32);
    if (!buf) return;

    int copy_size = 32;
    /* 步长16——但上限64超过usable=48 */
    if (variant > 50) {
        copy_size = 64;
    } else if (variant > 20) {
        copy_size = 48;
    }
    /* 跨步区间: [32,64]₁₆={32,48,64}→64>48→溢出 */
    memcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
           copy_size);
    free(buf);
}

int main(int argc, char **argv) {
    int v = argc > 1 ? atoi(argv[1]) : 0;
    aligned_copy_safe(v);
    aligned_copy_overflow(v);
    return 0;
}
