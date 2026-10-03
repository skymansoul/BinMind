/*
 * CVE-31: 拷贝大小来自外部 — memcpy长度来自函数参数, 无上界约束
 *
 * 模式: malloc(64), memcpy(buf, src, len) where len来自参数
 * 不可判定: len无约束 → INCONCLUSIVE (保守保留)
 * 这是CJ的保守设计: 无法证明安全时保留候选, 保证零漏报
 *
 * 对应: 类似 CVE-2018-1000001 (realpath 堆溢出, 外部输入控制长度)
 * 检测预期: INCONCLUSIVE (保守保留, 不过滤)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process(char *dst, const char *src, int len) {
    memcpy(dst, src, len);
}

int main(int argc, char **argv) {
    char *buf = (char *)malloc(64);
    if (!buf) return 1;

    int len = 0;
    if (argc > 1) len = atoi(argv[1]);
    /* len没有上界约束 → 无法证明安全或溢出 */

    char data[256];
    memset(data, 'L', sizeof(data));
    process(buf, data, len);

    printf("copy_size_external: len=%d\n", len);
    free(buf);
    return 0;
}
