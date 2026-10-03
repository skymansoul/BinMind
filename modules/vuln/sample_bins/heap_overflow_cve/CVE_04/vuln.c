/* CVE-2018-6789 — 堆溢出, 变量+偏移
 * 漏洞类型: 堆溢出 (写入大小 = 分配大小 + 4)
 * 触发条件: malloc(n), memcpy(buf, src, n+4)
 * 根因: 符号表达式 n+4 > n, Layer2应检出确溢出4字节
 * 有效原因: 测试符号关联分析对线性偏移的检测能力
 */
#include <stdlib.h>
#include <string.h>

void overflow_with_offset(char *src, size_t n) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    memcpy(buf, src, n + 4);  /* n+4 > n: 溢出4字节 */
    free(buf);
}

int main() {
    char data[256];
    overflow_with_offset(data, 64);
    return 0;
}
