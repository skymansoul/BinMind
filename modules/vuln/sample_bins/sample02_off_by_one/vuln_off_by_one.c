/* sample02: Off-by-one 堆溢出 — 循环边界差1
 *
 * 漏洞类型: Off-by-one heap overflow
 * 触发条件: for(i=0; i<=n; i++) 多写了一字节
 * 测试价值: 细粒度的边界错误, 检测是否考虑分配器padding
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copy_with_off_by_one(const char *src, size_t n) {
    char *buf = (char *)malloc(n);
    if (!buf) return;
    // [VULN] i<=n 导致写入 n+1 个字节, 第n字节在分配范围之外
    for (size_t i = 0; i <= n; i++) {
        buf[i] = src[i];
    }
    printf("buf: %s\n", buf);
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <string>\n", argv[0]); return 1; }
    size_t len = strlen(argv[1]);
    copy_with_off_by_one(argv[1], len);
    return 0;
}
