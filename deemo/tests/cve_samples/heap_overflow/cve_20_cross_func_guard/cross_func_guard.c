/*
 * CVE-20: 跨函数guard约束 — alloc在funcA, write在funcB, guard在funcA
 *
 * 模式: helper函数分配并做guard检查, 调用者写入
 * 触发: 无FM边界推理时, CJ无法关联guard→误报
 * 安全: guard限制 n<=128, usable(128)=136, write=n+4<=132 < 136 → SAFE
 *
 * 对应: 类似 CVE-2019-17666 (rtlwifi 堆溢出, 跨函数alloc/write)
 * 检测预期: CJ+跨函数传播应判定SAFE, 无跨函数传播则INCONCLUSIVE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *alloc_buf(int n) {
    if (n > 128) return NULL;
    return (char *)malloc(n);
}

void write_buf(char *buf, int n) {
    int i;
    for (i = 0; i < n; i++) {
        buf[i] = 'A';
    }
}

int main(void) {
    int n = 100;
    char *buf = alloc_buf(n);
    if (!buf) return 1;
    write_buf(buf, n);
    printf("cross_func_guard done\n");
    free(buf);
    return 0;
}
