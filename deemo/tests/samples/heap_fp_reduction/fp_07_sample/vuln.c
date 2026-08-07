/*
 * FP-07: 指针偏移后合法访问
 *
 * p = buf + 32; p[0..31] 访问 buf[32..63], 而 buf=malloc(64)。
 * 简单分析可能将 p[0] 视为 "offset 0" 而忽略 p 是 buf+32 的派生。
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(void) {
    char *buf = malloc(64);
    if (!buf) return 1;
    memset(buf, 0, 64);
    char *p = buf + 32;
    memset(p, 'X', 32);  // 写入 buf[32..63], 在 64B 范围内
    printf("buf[32]=%c buf[63]=%c\n", buf[32], buf[63]);
    free(buf);
    return 0;
}
