/*
 * CVE-40: 多重guard安全 — 两个独立guard约束不同变量, 写入在交汇路径
 *
 * 模式:
 *   malloc(256);
 *   if(offset > 64) offset = 64;   // guard: offset <= 64
 *   memcpy(buf+offset, src, 200);  // write_end = offset + 200
 *
 * 全局CJ: guard "offset<=64" 混入约束系统
 *         write_end = offset + 200, offset<=64 → max write_end=264 <= usable(256)=264 → SAFE
 * PS-CJ:  写入路径上 offset<=64, write_end=offset+200, max=264 <= usable 264 → SAFE
 *
 * 安全: worst case offset=64, write_end=64+200=264 <= usable(256)=264 → SAFE (恰好)
 * 对应: 类似 CVE-2014-0160 (Heartbleed, multi-guard offset+size)
 * 检测预期: SAFE (guard约束offset, 固定copy 200B)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int offset = 64;
    char *buf = (char *)malloc(256);
    if (!buf) return 1;

    if (offset > 64) offset = 64;

    memcpy(buf + offset, "data", 200);
    printf("multi_guard_safe: offset=%d\n", offset);
    free(buf);
    return 0;
}
