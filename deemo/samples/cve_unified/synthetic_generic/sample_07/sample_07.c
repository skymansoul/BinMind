/*
 * sample_07 — 对齐边界测试: malloc(5) + 8字节写入.
 *
 * 漏洞分析: malloc(5) 在 ptmalloc2 中实际分配 32 字节 chunk,
 * usable size = 16 字节 (32 - 16 header).
 * 所以 8 字节写入在 offset=0 时是安全的.
 *
 * 这是一个 NON-VULN 样本 — 用于测试误报过滤.
 * 简单分析器会报告"5字节分配写入8字节", 但考虑了堆模型后应判定为安全.
 *
 * 预期: 我们的检测器 → SAFE (正确), 简单检测器 → FALSE POSITIVE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *buf = (char *)malloc(5);
    if (!buf) return 1;

    /* 写入 8 字节 — 在 ptmalloc2 下应该安全 (usable=16) */
    long long val = 0x4142434445464748LL;
    memcpy(buf, &val, 8);

    printf("buf = %s\n", buf);
    free(buf);
    return 0;
}
