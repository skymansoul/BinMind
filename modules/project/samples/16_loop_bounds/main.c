/* 样本16: 循环写入 — 有边界检查但off-by-one
 * 模式: for(i=0;i<=n;i++) buf[i]=...; where malloc(n)
 *   边界检查用 <= 而非 <, 导致多写1字节
 * CVE参考: CVE-2018-1000001 模式的变种
 * 为何有效: 测试检测器对循环条件的精确语义理解
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 64;
    char *buf = (char *)malloc(n);
    if (!buf) return 1;

    /* 漏洞: i<=n 应为 i<n, 多写1字节 */
    for (int i = 0; i <= n; i++) {
        buf[i] = (char)(i & 0xFF);
    }

    printf("malloc(%d) wrote %d+1 bytes (off-by-one)\n", n, n);
    free(buf);
    return 0;
}
