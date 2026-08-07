/*
 * CVE-33: 跨路径guard安全 — guard在else分支, 写入在if分支
 *
 * 模式: if(n > 64) { memcpy(buf, src, 64); } else { return; }
 * 全局CJ: guard "n<=64" 被混入, 但写入路径上n可以是任意值
 *         实际写入64B, malloc(64) usable=72 → SAFE
 * PS-CJ:  if路径上无guard(写入路径), 写入64 < usable 72 → SAFE
 *         else路径上return, 无写入 → 不可行路径
 *
 * 安全: memcpy固定64B, usable(64)=72, 64 <= 72 → SAFE
 * 对应: 类似 CVE-2019-16995 (Linux kernel heap overflow, 分支隔离)
 * 检测预期: PS-CJ应判定PROVEN_SAFE, 全局CJ可能INCONCLUSIVE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int n = 100;
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    if (n > 64) {
        memcpy(buf, "hello", 64);
    } else {
        free(buf);
        return 0;
    }

    printf("cross_path_guard_safe: n=%d\n", n);
    free(buf);
    return 0;
}
