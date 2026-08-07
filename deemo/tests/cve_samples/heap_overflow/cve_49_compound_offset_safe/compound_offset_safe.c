#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * CVE-49: 复合算术偏移安全 — offset由多变量算术构成
 *
 * 模式: malloc(256);
 *       if (base > 64) base = 64;
 *       if (stride > 4) stride = 4;
 *       if (extra > 32) extra = 32;
 *       off = base * stride + extra;  // max = 64*4+32 = 288
 *       memcpy(buf + off, src, 8);   // write_end = 288+8 = 296
 *       实际: off最大=64*4+32=288, write_end=296 > usable(256)=264 → 应溢出
 *       但需要精确分析复合算术 → 检测器可能因表达式复杂而INCONCLUSIVE
 * 重设: 让结果安全 → base最大16, stride最大4, extra最大32
 *       off = 16*4+32 = 96, write_end = 96+8 = 104 <= 264 → SAFE
 */
int main(int argc, char **argv) {
    int base = 8, stride = 2, extra = 16;
    if (argc > 1) base = atoi(argv[1]);
    if (argc > 2) stride = atoi(argv[2]);
    if (argc > 3) extra = atoi(argv[3]);

    if (base > 16) base = 16;
    if (stride > 4) stride = 4;
    if (extra > 32) extra = 32;

    char *buf = (char *)malloc(256);
    if (!buf) return 1;

    int off = base * stride + extra;
    char src[16];
    memset(src, 'F', 16);
    memcpy(buf + off, src, 8);

    printf("compound_offset_safe: off=%d\n", off);
    free(buf);
    return 0;
}
