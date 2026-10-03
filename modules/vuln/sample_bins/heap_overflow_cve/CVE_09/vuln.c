/* CVE-2020-25692 — 堆溢出, 循环写入越界
 * 漏洞类型: 堆溢出 (循环写入超过分配)
 * 触发条件: malloc(n), 循环写入n+k次
 * 根因: 分配n, 循环边界为n+8, 每次写1字节
 * 有效原因: 测试循环写入场景的区间分析
 */
#include <stdlib.h>
#include <string.h>

void loop_overflow(size_t n) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    size_t i;
    for (i = 0; i <= n; i++) {   /* i从0到n: 共n+1次, 溢出1字节 */
        buf[i] = 'A';
    }
    free(buf);
}

int main() {
    loop_overflow(64);
    return 0;
}
