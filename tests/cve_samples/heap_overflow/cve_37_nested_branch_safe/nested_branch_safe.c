/*
 * CVE-37: 嵌套分支安全 — 多层guard在不同路径上, 写入受双层约束
 *
 * 模式:
 *   malloc(256);
 *   if(n > 200) { return; }
 *   if(n > 128) { memcpy(buf, src, 128); }
 *   else        { memcpy(buf, src, 64); }
 *
 * 全局CJ: 两个guard "n<=200" 和 "n<=128" 混入, 可能过度约束
 * PS-CJ:  路径1: n<=200, n<=128, write=64 <= usable(256)=264 → SAFE
 *         路径2: n<=200, n>128, write=128 <= 264 → SAFE
 *         两条路径都SAFE → PROVEN_SAFE
 *
 * 安全: 最大写入128B, usable(256)=264, 128 <= 264 → SAFE
 * 对应: 类似 CVE-2021-3156 (Sudo heap overflow, nested guards)
 * 检测预期: PROVEN_SAFE (需要PS-CJ区分两条写入路径)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int n = 100;
    char *buf = (char *)malloc(256);
    if (!buf) return 1;

    if (n > 200) {
        free(buf);
        return 0;
    }

    if (n > 128) {
        memcpy(buf, "data_pad", 128);
    } else {
        memcpy(buf, "data", 64);
    }

    printf("nested_branch_safe: n=%d\n", n);
    free(buf);
    return 0;
}
