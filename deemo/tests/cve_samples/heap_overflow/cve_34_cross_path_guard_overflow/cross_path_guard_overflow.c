/*
 * CVE-34: 跨路径guard溢出 — guard在else分支, 写入在if分支且超出
 *
 * 模式: if(n > 32) { memcpy(buf, src, 80); } else { return; }
 * 全局CJ: guard "n<=32" 被混入约束系统, 但写入路径上n>32且写入80B
 *         可能误用guard判定write_end=80 <= usable(64)=72? 80>72 → OVERFLOW
 * PS-CJ:  if路径上无guard, 写入80 > usable 72 → PROVEN_OVERFLOW
 *
 * 溢出: malloc(64) usable=72, memcpy 80B > 72 → OVERFLOW
 * 对应: 类似 CVE-2020-9496 (Apache HTTP Server heap overflow)
 * 检测预期: PROVEN_OVERFLOW
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int n = 100;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    if (n > 32) {
        memcpy(buf, "AABBCCDDEE", 80);
    } else {
        free(buf);
        return 0;
    }

    printf("cross_path_guard_overflow: n=%d\n", n);
    free(buf);
    return 0;
}
