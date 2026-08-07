/* CVE-2016-1000030 (安全陷阱) — 精确边界写入
 * 漏洞类型: 无溢出 (write_size == usable_size)
 * 触发条件: malloc(80), memcpy(buf, src, 80) — 请求80
 * 根因: 无漏洞; 写入恰好等于请求大小
 * 有效原因: 测试精确边界处不误报 (分配与写入同源变量)
 */
#include <stdlib.h>
#include <string.h>

void exact_copy(char *src) {
    size_t n = strlen(src) + 1;
    if (n > 80) n = 80;
    char *buf = (char *)malloc(n);
    if (!buf) return;
    memcpy(buf, src, n);   /* n==n, 精确边界, 安全 */
    free(buf);
}

int main() {
    char data[64] = "Hello";
    exact_copy(data);
    return 0;
}
