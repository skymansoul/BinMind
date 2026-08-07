/* CVE-2020-9802 (安全陷阱) — 上界守卫保护的写入
 * 漏洞类型: 无溢出 (guard + 分配=写入同源)
 * 触发条件: malloc(n+8), memcpy(buf, src, n) 其中 n<=64
 * 根因: 无漏洞; 写入受n<=64守卫且分配=n+8>64
 * 有效原因: 测试PcWBI守卫上界判定能否消除误报
 */
#include <stdlib.h>
#include <string.h>

void guarded_copy(char *src, size_t n) {
    if (n > 64) return;              /* 守卫: n<=64 */
    char *buf = (char *)malloc(n + 8);
    if (!buf) return;
    memcpy(buf, src, n);             /* n <= 64 < n+8, 安全 */
    free(buf);
}

int main() {
    char data[128] = "test";
    guarded_copy(data, 16);
    return 0;
}
