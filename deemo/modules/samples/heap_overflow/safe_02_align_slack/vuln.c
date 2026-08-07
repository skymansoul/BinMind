/*
 * 安全对照样本 B — 分配器对齐松弛 (TN)
 * 目标: 验证 request2usable 松弛能抑制误报
 * malloc(13) 实际可用 24B, 写入 18B 在边界内
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(13);       /* usable = 24B */
    if (!buf) return 1;
    /* 18B 写入: 13 < 18 < 24 → 实际安全, 纯比较误报 */
    memcpy(buf, "0123456789ABCDEFGH", 18);
    free(buf);
    return 0;
}
