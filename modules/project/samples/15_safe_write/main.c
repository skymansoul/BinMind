/* 样本15: 误报测试 — 安全的堆写入 (不应检出)
 * 模式: malloc(256) + memcpy(128) — 写入在分配范围内, 安全
 * 用途: 验证检测器不会对安全写入产生误报
 *   传统模式匹配工具会对memcpy报警, 但我们的值域分析
 *   应识别出128 ≤ 256 从而不报告
 * 预期: 0个发现 (无误报)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(256);
    if (!buf) return 1;

    /* 安全: 写入128B 到 256B分配的缓冲区 */
    memset(buf, 'S', 128);
    printf("safe: wrote 128B into 256B buffer\n");

    free(buf);
    return 0;
}
