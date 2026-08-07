/* CVE-2019-17571 — bounds check后安全(误报测试用)
 * 漏洞类型: 无溢出 (有bounds check保护)
 * 触发条件: malloc(256), if(n>256) return, memcpy(buf,src,n)
 * 根因: 路径约束n<=256, 写入<=分配, 安全
 * 有效原因: 测试DDSCC Layer3 SMT路径约束验证能否消除误报
 */
#include <stdlib.h>
#include <string.h>

void bounded_copy(char *src, size_t n) {
    char *buf = (char *)malloc(256);
    if (!buf) return;
    if (n > 256) {              /* bounds check */
        free(buf);
        return;
    }
    memcpy(buf, src, n);        /* n <= 256, 安全 */
    free(buf);
}

int main() {
    char data[512];
    bounded_copy(data, 128);
    return 0;
}
