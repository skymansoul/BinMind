/* 样本04: 循环中的堆溢出 — for(i=0;i<n;i++)写入固定大小buf
 * 模式: 循环边界n > 分配大小, 每轮写1字节但总写入超出
 * CVE参考: CVE-2017-1000251 (Linux kernel BlueZ, 循环构建数据包)
 * 触发条件: 循环次数来自外部输入, 超过分配大小
 * 为何有效: 测试检测器对循环累积写入的建模能力
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void fill_buffer(char *buf, int count) {
    for (int i = 0; i < count; i++) {
        buf[i] = (char)(i & 0xFF); /* 无边界检查的循环写入 */
    }
}

int main(int argc, char **argv) {
    int alloc_sz = 64;
    int n = argc > 1 ? atoi(argv[1]) : 128;

    char *buf = (char *)malloc(alloc_sz);
    if (!buf) return 1;

    fill_buffer(buf, n);  /* 漏洞: n=128 > alloc_sz=64 */
    printf("filled %d bytes into %d-byte buffer\n", n, alloc_sz);
    free(buf);
    return 0;
}
