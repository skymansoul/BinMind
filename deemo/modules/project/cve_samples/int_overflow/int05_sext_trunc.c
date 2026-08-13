// int05_sext_trunc: movsxd 符号扩展截断 → 负值扩展为极大值
// 模式: 32位负值通过movsxd扩展到64位, 若用于长度计算误解
// 预期检测: Mode 5 (SEXT_TRUNC) — 符号扩展截断
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned int u = 0x80000000;
    long long w = (long long)(int)u;
    printf("%lld\n", w);
    return 0;
}
