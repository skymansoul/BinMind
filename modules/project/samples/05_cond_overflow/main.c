/* 样本05: 条件堆溢出 — 仅在特定分支溢出
 * 模式: if(cond) memcpy(buf, src, large) else memcpy(buf, src, small)
 * CVE参考: CVE-2014-0160 (Heartbleed: 条件触发的溢出读取)
 * 触发条件: cond为真时溢出
 * 为何有效: 测试检测器对流程敏感溢出的处理 — 静态分析应报告两个分支
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    int mode = argc > 1 ? atoi(argv[1]) : 0;

    if (mode == 0) {
        /* 安全路径: 写入在分配范围内 */
        memset(buf, 0, 32);
        printf("safe: wrote 32 bytes\n");
    } else {
        /* 溢出路径: 写入超过分配大小 */
        memset(buf, 'A', 256);
        printf("overflow: wrote 256 bytes into 64-byte buffer\n");
    }

    free(buf);
    return 0;
}
