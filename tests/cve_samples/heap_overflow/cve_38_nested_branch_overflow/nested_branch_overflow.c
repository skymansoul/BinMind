/*
 * CVE-38: 嵌套分支溢出 — 一条路径安全, 另一条路径溢出
 *
 * 模式:
 *   malloc(64);
 *   if(n > 200) { return; }
 *   if(n > 32)  { memcpy(buf, src, 80); }   // 80 > usable(64)=72 → OVERFLOW
 *   else        { memcpy(buf, src, 32); }   // 32 <= 72 → SAFE
 *
 * 全局CJ: guard "n<=200" 和 "n<=32" 混入
 *         可能用n<=32的guard判定80B写入安全(误报过滤) → 错误SAFE
 * PS-CJ:  路径1: n<=200, n<=32, write=32 <= 72 → SAFE
 *         路径2: n<=200, n>32, write=80 > 72 → OVERFLOW
 *         任一路径OVERFLOW → PROVEN_OVERFLOW (保守保留)
 *
 * 溢出: if(n>32)路径, 80B > usable(64)=72 → OVERFLOW
 * 对应: 类似 CVE-2020-6096 (glibc heap overflow, partial path overflow)
 * 检测预期: PROVEN_OVERFLOW (PS-CJ应发现溢出路径; 全局CJ可能误判SAFE)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int n = 100;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    if (n > 200) {
        free(buf);
        return 0;
    }

    if (n > 32) {
        memcpy(buf, "AABBCCDD", 80);
    } else {
        memcpy(buf, "data", 32);
    }

    printf("nested_branch_overflow: n=%d\n", n);
    free(buf);
    return 0;
}
