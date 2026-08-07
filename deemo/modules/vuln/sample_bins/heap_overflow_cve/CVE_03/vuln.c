/* CVE-2020-2551 — 同变量分配(误报测试用)
 * 漏洞类型: 无溢出 (安全代码, 不应报告)
 * 触发条件: malloc(n) + memcpy(buf, src, n), 同变量
 * 根因: 无漏洞, 分配大小=写入大小
 * 有效原因: 正确代码, 测试DDSSC Layer2符号关联能否消除误报
 */
#include <stdlib.h>
#include <string.h>

void safe_copy(char *src, size_t n) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    memcpy(buf, src, n);    /* n == n: 安全, 不应报告 */
    free(buf);
}

int main() {
    char data[128] = "test";
    safe_copy(data, 64);
    return 0;
}
